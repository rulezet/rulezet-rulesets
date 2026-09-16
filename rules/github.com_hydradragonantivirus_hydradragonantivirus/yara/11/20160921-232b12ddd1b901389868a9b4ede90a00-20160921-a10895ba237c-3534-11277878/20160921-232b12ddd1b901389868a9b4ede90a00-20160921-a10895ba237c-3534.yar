rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_a10895ba237c_3534 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_d44650cb742ce4feede24ebce4407e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash3       = "5d3f7264c4109728074b6f96ac9910bb0072014149731ab6e6b307d40d5c37ff"

  strings:
    $s1 = ")(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck" ascii
    $s2 = "urn \"OQr\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s3 = "eturn \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii
    $s4 = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy" ascii
    $s5 = "rn \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(f" ascii
    $s6 = ")(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}