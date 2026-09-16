rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c3da76a3c22d097ead7fe4dc4caf3dd70bec37110bb88e4788126f43c7f1a4"

  strings:
    $s1  = "c:\\documents and settings\\bart\\mijn documenten\\visual studio projects\\openssl\\crypto\\ec\\ec2_smpt.c" fullword ascii
    $s2  = "%s: unable to resolve host address `%s'" fullword ascii
    $s3  = "?to - (pool->contents + pool->tail) <= end - beg" fullword ascii
    $s4  = "       --content-disposition   honor the Content-Disposition header when" fullword ascii
    $s5  = "Inserted `%s' into basic_authed_hosts" fullword ascii
    $s6  = "#@Mail bug reports and suggestions to <bug-wget@gnu.org>." fullword ascii
    $s7  = "Found `%s' in basic_authed_hosts." fullword ascii
    $s8  = "N@%s: %s: Invalid header `%s'." fullword ascii
    $s9  = "Host `%s' has not issued a general basic challenge." fullword ascii
    $s10 = "pB%s: %s: Invalid byte value `%s'" fullword ascii
    $s11 = "wrote `%s' to STORE" fullword ascii
    $s12 = "Saving to: `%s'" fullword ascii
    $s13 = "lhash part of OpenSSL 0.9.8i 15 Sep 2008" fullword ascii
    $s14 = "KGS!@#$%Found %d broken links." fullword ascii
    $s15 = "%s: cannot verify %s's certificate, issued by `%s':" fullword ascii
    $s16 = "%s: %s: Invalid restriction `%s', use [unix|windows],[lowercase|uppercase],[nocontrol]." fullword ascii
    $s17 = "       --auth-no-challenge     Send Basic HTTP authentication information" fullword ascii
    $s18 = "SHA part of OpenSSL 0.9.8i 15 Sep 2008" fullword ascii
    $s19 = "Stack part of OpenSSL 0.9.8i 15 Sep 2008" fullword ascii
    $s20 = "IDEA part of OpenSSL 0.9.8i 15 Sep 2008" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}