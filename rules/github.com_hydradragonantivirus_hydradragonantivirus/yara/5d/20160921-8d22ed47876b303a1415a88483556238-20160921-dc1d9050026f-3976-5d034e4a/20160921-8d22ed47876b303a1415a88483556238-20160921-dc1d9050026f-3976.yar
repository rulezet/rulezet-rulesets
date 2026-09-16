rule _20160921_8d22ed47876b303a1415a88483556238_20160921_dc1d9050026f_3976 {
  meta:
    description = "datamaliciousorder - from files 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash2       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash3       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "0(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SEo\";" ascii
    $s2 = "\"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(func" ascii
    $s3 = "{return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})" ascii
    $s4 = "f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Lp" ascii
    $s5 = "tion f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return" ascii
    $s6 = "(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}