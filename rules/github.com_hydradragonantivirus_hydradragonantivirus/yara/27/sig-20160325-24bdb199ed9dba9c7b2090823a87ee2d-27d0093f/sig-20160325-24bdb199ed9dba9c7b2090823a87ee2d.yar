rule sig_20160325_24bdb199ed9dba9c7b2090823a87ee2d {
  meta:
    description = "datamaliciousorder - file 20160325_24bdb199ed9dba9c7b2090823a87ee2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93e053d583981dbf89d4693d156bd55553d162e3e867c8b8a8b7eb9668c87d96"

  strings:
    $s1  = "responseHeaders = rsibling[\"Exp\" + head + \"ironm\" + nextSibling + \"Strin\" + string](\"%TE\" + matcherFromGroupMatchers) + " ascii
    $s2  = "responseHeaders = rsibling[\"Exp\" + head + \"ironm\" + nextSibling + \"Strin\" + string](\"%TE\" + matcherFromGroupMatchers) + " ascii
    $s3  = "password = \"p://\"," fullword ascii
    $s4  = " attaches + \".\" + hash + \"r\";" fullword ascii
    $s5  = "n, 68, wait, 2) * (tabIndex, 100, defaultView) * (2 & rpseudo));" fullword ascii
    $s6  = "source[\"Sle\" + divStyle](((nextAll + 1809) + (dataUser | 1100)));" fullword ascii
    $s7  = "function append(rattributeQuotes, postSelector, newUnmatched, delay) {" fullword ascii
    $s8  = "function textContent() {" fullword ascii
    $s9  = "textContent(handler, interval, runescape);" fullword ascii
    $s10 = "source = suffix[\"WScr\" + innerHTML];" fullword ascii
    $s11 = "matcherIn = new guid[\"Activ\" + focusin + \"bject\"](linear + \"Str\" + addHandle);" fullword ascii
    $s12 = "inPage[\"s\" + createPseudo + \"n\" + start]();" fullword ascii
    $s13 = "fast[handler + \"e\"]();" fullword ascii
    $s14 = "function holdReady() {" fullword ascii
    $s15 = "second = \"com/fa\", fadeOut = \"Acti\", focusin = \"eXO\";" fullword ascii
    $s16 = "rsibling = source[\"Cre\" + slideToggle + \"ect\"](preFilter + \"ipt.S\" + runescape);" fullword ascii
    $s17 = "eval(conditionFn(\"append%28%22Respon%22%20+%20pointerenter%20+%20%22y%22%2C%20%28Math.pow%28%28inArray%2614%29%2C%20%28isArray+" ascii
    $s18 = "var hash = \"sc\"," fullword ascii
    $s19 = "easing[\"WScri\" + v][\"Sleep\"]((defaultView & 7) * (rCRLF, 238, opacity, 2) * (id / 49) * (isArray + 1) * (defaultView & 7) * " ascii
    $s20 = "holdReady(wait);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}