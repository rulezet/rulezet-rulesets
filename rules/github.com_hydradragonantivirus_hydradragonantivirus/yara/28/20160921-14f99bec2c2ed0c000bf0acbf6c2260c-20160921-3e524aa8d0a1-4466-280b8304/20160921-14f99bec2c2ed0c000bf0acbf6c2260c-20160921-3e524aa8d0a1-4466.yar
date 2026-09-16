rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_3e524aa8d0a1_4466 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash3       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash4       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash5       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"
    hash6       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "{return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(" ascii
    $s2 = "n\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3 = "n\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s4 = "){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";" ascii
    $s5 = "unction f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}