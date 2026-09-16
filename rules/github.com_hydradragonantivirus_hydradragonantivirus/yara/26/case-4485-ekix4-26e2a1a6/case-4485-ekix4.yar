import "pe"
rule case_4485_ekix4 {
  meta:
    description = "4485 - file ekix4.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-07-13"
    hash1       = "e27b71bd1ba7e1f166c2553f7f6dba1d6e25fa2f3bb4d08d156073d49cbc360a"

  strings:
    $s1  = "f159.dll" fullword ascii
    $s2  = "AppPolicyGetProcessTerminationMethod" fullword ascii
    $s3  = "ossl_store_get0_loader_int" fullword ascii
    $s4  = "loader incomplete" fullword ascii
    $s5  = "log conf missing description" fullword ascii
    $s6  = "SqlExec" fullword ascii
    $s7  = "process_include" fullword ascii
    $s8  = "EVP_PKEY_get0_siphash" fullword ascii
    $s9  = "process_pci_value" fullword ascii
    $s10 = "EVP_PKEY_get_raw_public_key" fullword ascii
    $s11 = "EVP_PKEY_get_raw_private_key" fullword ascii
    $s12 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii
    $s13 = "divisor->top > 0 && divisor->d[divisor->top - 1] != 0" fullword wide
    $s14 = "ladder post failure" fullword ascii
    $s15 = "operation fail" fullword ascii
    $s16 = "ssl command section not found" fullword ascii
    $s17 = "log key invalid" fullword ascii
    $s18 = "cms_get0_econtent_type" fullword ascii
    $s19 = "log conf missing key" fullword ascii
    $s20 = "ssl command section empty" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 11000KB and
    (pe.imphash() == "547a74a834f9965f00df1bd9ed30b8e5" or 8 of them)
}