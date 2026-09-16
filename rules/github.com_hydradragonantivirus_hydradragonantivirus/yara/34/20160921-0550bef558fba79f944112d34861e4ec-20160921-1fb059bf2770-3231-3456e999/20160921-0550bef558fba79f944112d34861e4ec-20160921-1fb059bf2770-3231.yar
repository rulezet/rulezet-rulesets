rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_1fb059bf2770_3231 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "l\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function" ascii
    $s2 = "ction f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s3 = "ion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s4 = "rn \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6 = ")(),(function f000(){return \"Ot\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}