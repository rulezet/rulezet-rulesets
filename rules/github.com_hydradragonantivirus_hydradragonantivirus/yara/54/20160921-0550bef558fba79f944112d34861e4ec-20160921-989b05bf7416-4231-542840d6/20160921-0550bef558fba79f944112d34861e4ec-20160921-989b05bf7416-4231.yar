rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_989b05bf7416_4231 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_e432cba10cde369693d6b125dda112c7.js, 20160922_41319625a3342333693d5eefb82a43ce.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash4       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"
    hash5       = "6cb4a85918ba85e72bd611e7820ea056409f5f25a58a8d15335e282229f10af9"
    hash6       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "nction f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){retu" ascii
    $s2 = "\"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(funct" ascii
    $s3 = "{return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})" ascii
    $s4 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){retur" ascii
    $s5 = "(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}