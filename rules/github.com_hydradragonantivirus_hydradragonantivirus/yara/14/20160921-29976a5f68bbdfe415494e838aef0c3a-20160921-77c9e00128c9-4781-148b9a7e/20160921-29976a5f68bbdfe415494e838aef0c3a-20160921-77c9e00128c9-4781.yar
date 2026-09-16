rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_77c9e00128c9_4781 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_cb6c4de61b30cd204129d0942321058c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash3       = "db98233c2508e4a2167ee46a334ce9052faa726615e89838f4fdb36b74fc5353"

  strings:
    $s1 = "f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"G" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Lo" ascii
    $s3 = "n \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s4 = "\"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s5 = "(),(function f000(){return \"RVb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}