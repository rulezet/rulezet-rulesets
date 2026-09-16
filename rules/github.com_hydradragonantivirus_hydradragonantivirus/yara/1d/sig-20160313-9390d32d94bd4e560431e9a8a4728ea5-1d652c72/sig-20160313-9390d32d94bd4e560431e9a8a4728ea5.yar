rule sig_20160313_9390d32d94bd4e560431e9a8a4728ea5 {
  meta:
    description = "datamaliciousorder - file 20160313_9390d32d94bd4e560431e9a8a4728ea5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88536a786ff6370078c4c91ea06b28c3d987eadcc587b78e5f8152331a10218a"

  strings:
    $s1  = "memory[\"op\" + size](\"G\" + type, \"http\" + text + \"ohel\" + fxNow + \"ff.\" + parents + \"70.exe\", !((((((61 & currentTime" ascii
    $s2  = "memory[\"op\" + size](\"G\" + type, \"http\" + text + \"ohel\" + fxNow + \"ff.\" + parents + \"70.exe\", !((((((61 & currentTime" ascii
    $s3  = "addGetHookIf[\"Ru\" + handleObjIn](optionSet, ((1 + -getWindow) | (0 & getWindow)), ((402 - extra), 0));" fullword ascii
    $s4  = "scripts = this[\"WScri\" + rcheckableType];" fullword ascii
    $s5  = "tokenize[cache + \"p\" + to] = (getWindow * 1);" fullword ascii
    $s6  = "y / 12) / (Math.pow(container, 2) - propFilter)))) & (((3 & (slideUp / 39)) | ((callbackInverse, 86, offsetHeight) + (27, pixelP" ascii
    $s7  = "  value = \"%TEMP\"," fullword ascii
    $s8  = "ight) - 48154), (unquoted, 139, Sizzle, 0)) / clientLeft * (2 | offsetHeight) * (2 + camelKey) * (3 + camelKey)))) == 3));" fullword ascii
    $s9  = "optionSet = removeClass[\"Exp\" + tweens + \"vir\" + obj + \"ntStr\" + cos + \"s\"](value + \"%/\") + getAllResponseHeaders + \"" ascii
    $s10 = "optionSet = removeClass[\"Exp\" + tweens + \"vir\" + obj + \"ntStr\" + cos + \"s\"](value + \"%/\") + getAllResponseHeaders + \"" ascii
    $s11 = "memory[responseText + \"en\" + eventDoc]();" fullword ascii
    $s12 = "memory = this[\"WScr\" + xhrFields][\"Create\" + updateFunc + \"ect\"](fixHook + \"2.X\" + add);" fullword ascii
    $s13 = "rescape[shift + \"File\"](optionSet, ((abort - 45) * (fontWeight / 21)));" fullword ascii
    $s14 = "rescape = this[\"WScr\" + xhrFields][\"Cre\" + innerHTML + \"ect\"]($ + \".Stre\" + dirruns);" fullword ascii
    $s15 = "function _evalUrl() {" fullword ascii
    $s16 = "function rwhitespace() {" fullword ascii
    $s17 = "function handleObj() {" fullword ascii
    $s18 = "type = \"ET\";" fullword ascii
    $s19 = "  extra = 152," fullword ascii
    $s20 = "var size = \"en\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}