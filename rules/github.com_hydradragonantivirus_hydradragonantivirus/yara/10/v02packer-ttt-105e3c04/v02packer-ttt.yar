import "pe"
rule _v02Packer__ttt_
{
	meta:
		description = "v.02Packer -> tt.t"
	strings:
		$0 = {60 E8 36 FE FF FF C3 90 ?? 00}
	condition:
		$0 at pe.entry_point
}