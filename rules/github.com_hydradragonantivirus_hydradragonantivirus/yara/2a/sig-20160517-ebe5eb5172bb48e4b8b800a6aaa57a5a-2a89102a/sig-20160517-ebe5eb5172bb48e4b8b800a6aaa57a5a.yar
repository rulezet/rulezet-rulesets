rule sig_20160517_ebe5eb5172bb48e4b8b800a6aaa57a5a {
  meta:
    description = "datamaliciousorder - file 20160517_ebe5eb5172bb48e4b8b800a6aaa57a5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b8f843f759be8c4417058305fe135d380b21fd795cd916b973222baba990f2"

  strings:
    $s1 = "var uoxz2='vmpavlavtvycrp3tsn wpbf3ghlpr4jbjjzu1zvkcqxsqkuouhqqkibe43ji1bfyu1qh4jk4vqmysscasian=sverf\\'wzjtjtuytutczvwdgnqlwxei" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   bytbnd2m4=r4+\"v\"+\"al\";   WScript.lister=5;   bytbnd2m4=\"\"+\"s\";   ww=232323;   }catch(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}