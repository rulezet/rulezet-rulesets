rule Trojan_Danger_Generic_Dacic_1A7FA519_A_C12F0145_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.C12F0145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114d521cc40a190c16789b57557706d213f73922ec048c2e74003df43af825f9"

  strings:
    $s1 = "\\Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}