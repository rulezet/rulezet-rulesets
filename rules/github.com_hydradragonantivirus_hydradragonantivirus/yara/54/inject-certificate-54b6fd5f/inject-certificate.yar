rule Inject_Certificate 
{
    meta:
        author = "x0r"
        description = "Inject certificate in store"
    strings:
        $f1 = "Crypt32.dll" nocase
        $r1 = "software\\microsoft\\systemcertificates\\spc\\certificates" nocase
        $c1 = "CertOpenSystemStore" 
    condition:
	all of them
}