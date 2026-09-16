rule _20160921_85f6e34eb7e2f53408ead6aab6d7f923_20160921_a1cbb43a1e22_5473 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_da7f7f057c35b886425ec822f654da90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash2       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash3       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"

  strings:
    $s1 = "UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(functi" ascii
    $s2 = "00(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs" ascii
    $s3 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})()," ascii
    $s4 = "n \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s5 = ";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}