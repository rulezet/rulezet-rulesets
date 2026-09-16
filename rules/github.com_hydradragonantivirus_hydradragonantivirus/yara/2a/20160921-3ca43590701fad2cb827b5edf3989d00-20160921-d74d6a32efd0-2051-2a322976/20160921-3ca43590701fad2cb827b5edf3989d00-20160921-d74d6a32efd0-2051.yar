rule _20160921_3ca43590701fad2cb827b5edf3989d00_20160921_d74d6a32efd0_2051 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ca43590701fad2cb827b5edf3989d00.js, 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"
    hash2       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"

  strings:
    $s1 = "m\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yv\";})(),(function f000(){re" ascii
    $s3 = "(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s4 = "(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){" ascii
    $s5 = ";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000" ascii
    $s6 = "unction f000(){return \"ZGq\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s7 = "00(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s8 = "n \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s9 = " \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}