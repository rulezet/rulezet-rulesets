rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_2eacd3ef1ce6_4350 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160921_95ced062e0552048d29cf59daab852db.js, 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"
    hash4       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash5       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash6       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "eturn \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})()," ascii
    $s2 = "\"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(funct" ascii
    $s3 = ",(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){r" ascii
    $s4 = "n f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"M" ascii
    $s5 = "ction f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}