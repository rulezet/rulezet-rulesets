rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_a977d2870f5e_4605 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1 = " \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s2 = "nction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s3 = "n \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s4 = "),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s5 = "\"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}