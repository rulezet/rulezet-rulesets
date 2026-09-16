rule _20160921_0393cc83501a7f5f46bdb6e7b413461e_20160921_06b8a8ba37bd_1768 {
  meta:
    description = "datamaliciousorder - from files 20160921_0393cc83501a7f5f46bdb6e7b413461e.js, 20160921_06b8a8ba37bdbe66227238ed6343de45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89c5611205911dc22a002122b9f40afc236a2afc8f46d1c947520bc93cc73857"
    hash2       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"

  strings:
    $s1  = " \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s2  = "\"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s3  = "n \"Qj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s4  = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s5  = "ion f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s6  = "function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){ret" ascii
    $s7  = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(" ascii
    $s8  = "000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s9  = "f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"R" ascii
    $s10 = "){return \"PTi\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}