rule _20160921_da4ec6dae2eccab30a5e229082e39a40_20160921_eb80446b9cea_5717 {
  meta:
    description = "datamaliciousorder - from files 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash2       = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"

  strings:
    $s1 = ",(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s2 = "urn \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s3 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Go\";})(),(function f00" ascii
    $s4 = "n f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"" ascii
    $s5 = "turn \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}