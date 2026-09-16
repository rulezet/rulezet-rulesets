rule _20160921_c459056d51b1a4ea3176139800021b35_20160921_d6dc24b88112_2164 {
  meta:
    description = "datamaliciousorder - from files 20160921_c459056d51b1a4ea3176139800021b35.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1 = "urn \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s2 = "f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OU" ascii
    $s3 = " f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"D" ascii
    $s4 = "function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s5 = " f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"T" ascii
    $s6 = "})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s7 = "{return \"RLk\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(" ascii
    $s8 = "0(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\"" ascii
    $s9 = "unction f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}