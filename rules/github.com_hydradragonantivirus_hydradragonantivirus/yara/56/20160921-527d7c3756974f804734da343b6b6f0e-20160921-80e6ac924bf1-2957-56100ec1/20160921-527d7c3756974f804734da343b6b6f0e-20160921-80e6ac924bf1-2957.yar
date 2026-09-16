rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_80e6ac924bf1_2957 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash3       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "urn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s3 = "Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";" ascii
    $s5 = ")(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NYh\";})(),(function f00" ascii
    $s6 = "ion f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s7 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}