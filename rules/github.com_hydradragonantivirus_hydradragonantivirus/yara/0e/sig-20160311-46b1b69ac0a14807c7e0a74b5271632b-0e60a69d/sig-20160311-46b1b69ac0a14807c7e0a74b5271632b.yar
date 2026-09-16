rule sig_20160311_46b1b69ac0a14807c7e0a74b5271632b {
  meta:
    description = "datamaliciousorder - file 20160311_46b1b69ac0a14807c7e0a74b5271632b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ef14417b4425fecfaed972d12ff8ef916eb094ecb8f60cf0eb0d22268b1a2f"

  strings:
    $s1  = "tern & 31)))) * ((Math.pow((clone, 239, pageX) * (3 + processData) * 2 * pageX, 2) - ((appendTo * 34) | (push_native / 32))) / (" ascii
    $s2  = "hooks[\"o\" + start + \"n\".safeActiveElement()](register + \"ET\", position + \"//pe\" + insertAfter + \"y_a\".safeActiveElemen" ascii
    $s3  = "rwhitespace[contexts + \"n\"](markFunction.safeActiveElement(((Math.pow(93, pageX) - 8517) - (winnow - 59))), ((appendTo & 1) + " ascii
    $s4  = "var async = \"WScri\", ajaxConvert = \"i\", processData = 0, push_native = 16384, pattern = 30;" fullword ascii
    $s5  = "rwhitespace[contexts + \"n\"](markFunction.safeActiveElement(((Math.pow(93, pageX) - 8517) - (winnow - 59))), ((appendTo & 1) + " ascii
    $s6  = "position = \"http:\"," fullword ascii
    $s7  = "matches = lock[guid + \"ate\" + using + \"ect\".safeActiveElement()](async + \"pt.S\" + getAll + \"l\");" fullword ascii
    $s8  = " \"epub\" + removeAttr + \"a.pl/\" + useCache + \"g5\".safeActiveElement(), !(max == (((((26 - transport) + (1 + -appendTo)) + (" ascii
    $s9  = "visible[iframe + \"p\".safeActiveElement() + el]();" fullword ascii
    $s10 = "getAll = \"hel\", isTrigger = \"WScr\", appendTo = 1, iterator = \"WScrip\", start = \"pe\", opener = \"dy\";" fullword ascii
    $s11 = "visible = responseType[isTrigger + \"ipt\"][guid + \"ateOb\".safeActiveElement() + mimeType](\"ADO\" + progressContexts + \"eam" ascii
    $s12 = "hooks[\"o\" + start + \"n\".safeActiveElement()](register + \"ET\", position + \"//pe\" + insertAfter + \"y_a\".safeActiveElemen" ascii
    $s13 = "option[\"ty\" + start] = appendTo;" fullword ascii
    $s14 = "lock = responseType[iterator + \"t\"];" fullword ascii
    $s15 = "visible[\"sav\" + toggleClass + \"File\".safeActiveElement()](markFunction, ((36 - fn) + (0 | appendTo)));" fullword ascii
    $s16 = "removeAttr = \"lik\", cleanData = \"ion\", onabort = \"c\", tag = 9, binary = \"Respo\";" fullword ascii
    $s17 = "iframe = \"o\", clone = 172;" fullword ascii
    $s18 = "jsonProp = 177, insertAfter = \"rfum\", transport = (function String.prototype.safeActiveElement() {" fullword ascii
    $s19 = "return active" fullword ascii
    $s20 = "propFix[initial]();" fullword ascii

  condition:
    uint16(0) == 0x6669 and
    8 of them
}