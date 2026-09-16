rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_7cd473b59463_3004 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "b\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mc\";})(),(fu" ascii
    $s3 = "{return \"DAp\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";}" ascii
    $s4 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZGq\";})(),(function f000" ascii
    $s5 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})()" ascii
    $s7 = "urn \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}