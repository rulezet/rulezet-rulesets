rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_0cff9f091048_4181 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash3       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash4       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash5       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s2 = "turn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})()" ascii
    $s3 = "){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})" ascii
    $s4 = "rn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s5 = "\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}