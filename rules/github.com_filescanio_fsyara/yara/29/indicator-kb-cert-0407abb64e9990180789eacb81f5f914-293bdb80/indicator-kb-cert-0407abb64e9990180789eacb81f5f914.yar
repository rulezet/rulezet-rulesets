import "pe"
rule INDICATOR_KB_CERT_0407abb64e9990180789eacb81f5f914 : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "bcb40c7d23c9db41766c780b5388fb70f3d570bf"
		hash = "f1fdac82e4e4da91ba2a9d8122a5f27e11a8342308b18376b189d2cc7468557b"
		score = 60

	condition:
		uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_signatures ) : ( pe.signatures [ i ] . subject contains "VideoLAN" and pe.signatures [ i ] . serial == "04:07:ab:b6:4e:99:90:18:07:89:ea:cb:81:f5:f9:14" )
}