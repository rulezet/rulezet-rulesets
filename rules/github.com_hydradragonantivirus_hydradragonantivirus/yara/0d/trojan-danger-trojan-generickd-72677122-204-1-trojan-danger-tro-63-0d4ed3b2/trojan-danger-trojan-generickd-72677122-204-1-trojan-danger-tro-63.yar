import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_204_1_Trojan_Danger_Tro_63 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_204_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_206_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_208_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_209_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63048561d8017a06fd1e5459b5a458679c24563b54108390b7b6a565b5794b14"
    hash2       = "465e4a5dfd61d15a5224013f399c6a872a728bd8e1befe4fd22283f9d83eab3a"
    hash3       = "6a250046cf56a98f17d6e55826504638725831d59bec0d3fa172c576ce0f6076"
    hash4       = "9163656d769716baef7403241a656f37c330de33e1afc96e9d7486cf48ae7874"

  strings:
    $s1 = "Fees for services listed in an ordering document are exclusive of taxes and expenses. You agree that you have not relied onOnlin" ascii
    $s2 = "Fees for services listed in an ordering document are exclusive of taxes and expenses. You agree that you have not relied onOnlin" ascii
    $s3 = "e Hosting Access Policies. Oracle University's Online Hosting Access Policies are located at" fullword ascii
    $s4 = "gegg*x*x*x#$#$16t72134418tlkgahp*x*x*x#$#$16q72134419qmpqvox*x*x*x#$#$16r72134421xcmghmf*x*x*x#$#$16q72134422weocmnm*x*x*x#$#$16" ascii
    $s5 = "RF Page licenses from Oracle." fullword ascii
    $s6 = "tars*x*x*x#$#$16u72134459wxgxodp*x*x*x#$#$16u7213450rrjcacey*x*x*x#$#$16a7213451rjqvidyu*x*x*x#$#$16b7213452umcuklte*x*x*x#$#$16" ascii
    $s7 = "Education Sales Office. If you choose not to renew the membership, all rights to use the Online Library shall cease.additional C" ascii
    $s8 = "Education Sales Office. If you choose not to renew the membership, all rights to use the Online Library shall cease.additional C" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1988d0f499743ee40268a60de09d4562" and (all of them)
    ) or (all of them)
}