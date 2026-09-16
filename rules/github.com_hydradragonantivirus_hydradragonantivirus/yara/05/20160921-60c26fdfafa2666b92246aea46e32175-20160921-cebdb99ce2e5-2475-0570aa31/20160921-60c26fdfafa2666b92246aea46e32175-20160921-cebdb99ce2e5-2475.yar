rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_cebdb99ce2e5_2475 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "eturn \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2 = "\"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s4 = "n\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s5 = "on f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s6 = "ction f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\";})(),(function f000(){retur" ascii
    $s7 = "0(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";}" ascii
    $s8 = "return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}