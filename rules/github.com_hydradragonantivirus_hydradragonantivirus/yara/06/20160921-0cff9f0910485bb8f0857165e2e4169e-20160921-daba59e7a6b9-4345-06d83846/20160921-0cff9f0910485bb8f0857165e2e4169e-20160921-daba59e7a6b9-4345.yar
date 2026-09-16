rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_daba59e7a6b9_4345 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "{return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DNa\";})" ascii
    $s2 = "tion f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s3 = ";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f00" ascii
    $s4 = ",(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s5 = ")(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DNa\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}