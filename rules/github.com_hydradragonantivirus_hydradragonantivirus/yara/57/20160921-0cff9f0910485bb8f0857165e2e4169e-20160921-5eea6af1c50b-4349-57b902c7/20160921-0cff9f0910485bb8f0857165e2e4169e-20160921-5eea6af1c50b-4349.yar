rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_5eea6af1c50b_4349 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "ction f000(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2 = "{return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";}" ascii
    $s3 = "on f000(){return \"BMj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "0(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\"" ascii
    $s5 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}