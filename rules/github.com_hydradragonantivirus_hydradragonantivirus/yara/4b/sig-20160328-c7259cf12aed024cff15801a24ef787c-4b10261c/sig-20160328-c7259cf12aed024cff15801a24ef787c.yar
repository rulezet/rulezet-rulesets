rule sig_20160328_c7259cf12aed024cff15801a24ef787c {
  meta:
    description = "datamaliciousorder - file 20160328_c7259cf12aed024cff15801a24ef787c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44f6ba27a2eb2355fc15247174f2f96eaf1c490f8e4a41c9ca27c8aa596750b3"

  strings:
    $s1  = "checkDisplay(returnValue(\"version%20%3D%20pointerleave%5B%22WScrip%22%20+%20clientTop%5D%5B%22Creat%22%20+%20register%20+%20%22" ascii
    $s2  = "if (letter[createPseudo] == ((Math.pow(39, setGlobalEval) - 1478) * (Math.pow(multipleContexts, 2) - notifyWith) + (28 & iterato" ascii
    $s3  = "if (letter[createPseudo] == ((Math.pow(39, setGlobalEval) - 1478) * (Math.pow(multipleContexts, 2) - notifyWith) + (28 & iterato" ascii
    $s4  = "checkDisplay(returnValue(\"letter%5Bcontents%20+%20%22p%22%20+%20expanded%5D%28%22G%22%20+%20splice%2C%20%22http%3A%22%20+%20rco" ascii
    $s5  = "function getPropertyValue(hash, addBack, superMatcher) {" fullword ascii
    $s6  = "properties[\"ty\" + createPositionalPseudo + \"e\"] = ((39 - Symbol) / (5 * setGlobalEval));" fullword ascii
    $s7  = "} catch (getScript) {" fullword ascii
    $s8  = "checkDisplay(returnValue(\"letter%5Bcontents%20+%20%22p%22%20+%20expanded%5D%28%22G%22%20+%20splice%2C%20%22http%3A%22%20+%20rco" ascii
    $s9  = "properties[byElement + \"eTo\" + pixelPositionVal](blur, ((createInputPseudo, 129, inspectPrefiltersOrTransports, 2)));" fullword ascii
    $s10 = "version[max + \"n\"](blur);" fullword ascii
    $s11 = "while (letter[setPositiveNumber + \"dySt\" + uniqueID] != ((5 | implementation) & (7 & createElement))) responseContainer[\"WScr" ascii
    $s12 = "checkDisplay(returnValue(\"letter%20%3D%20dequeue%5Bfile%20+%20%22ipt%22%5D%5BdefaultValue%20+%20%22ate%22%20+%20globalEval%20+%" ascii
    $s13 = "function chainable(backgroundClip, postFilter, createDocumentFragment) {" fullword ascii
    $s14 = "function getAllResponseHeaders(focus, curPosition) {" fullword ascii
    $s15 = "head%20%3D%20%28%22ADOD%22%29%2C%20tuple%20%3D%20%28%22str%22%29%3B%3B\"));" fullword ascii
    $s16 = "while (letter[setPositiveNumber + \"dySt\" + uniqueID] != ((5 | implementation) & (7 & createElement))) responseContainer[\"WScr" ascii
    $s17 = "pointerleave[\"WScrip\" + clientTop][\"Sl\" + param + \"p\"](((createTween | 166288) / (cssHooks | 35)));" fullword ascii
    $s18 = "properties[protocol + \"te\"](letter[rquery + \"ponse\" + cssNormalTransform]);" fullword ascii
    $s19 = "letter[dataType + \"e\" + buildParams + \"d\"]();" fullword ascii
    $s20 = "function flatOptions(evt, time, isReady) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}