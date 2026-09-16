rule sig_20170119_9951e6ca34456b6b715b9bbc9f3f1aa3 {
  meta:
    description = "datamaliciousorder - file 20170119_9951e6ca34456b6b715b9bbc9f3f1aa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b03322760b3bdd3159b1efdde7b05593f73bef3e517b7117ec75f78f6355609"

  strings:
    $s1 = "var ylohy2 = new Function(wyrgiqawunqahmonohopfecetkabgebwixhyxilrefukypozozxexcebmokyvovtifetusirimjoxredonidenjyqtomadoqvotegk" ascii
    $s2 = "var ylohy2 = new Function(wyrgiqawunqahmonohopfecetkabgebwixhyxilrefukypozozxexcebmokyvovtifetusirimjoxredonidenjyqtomadoqvotegk" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}