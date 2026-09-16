rule sig_20160328_28af04d0898dd15b81dd9554f67aa9c3 {
  meta:
    description = "datamaliciousorder - file 20160328_28af04d0898dd15b81dd9554f67aa9c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40f4e5067c78d78f47e4bedf1a6ee4b0a26565fae71bd0943f17eaf022de3a2b"

  strings:
    $s1  = "resolve(implicitRelative(\"DOMParser%28%22http%3A/%22%20+%20getElementById%20+%20%22giont%22%20+%20tokenCache%20+%20%22.su/%22%2" ascii
    $s2  = "resolve(implicitRelative(\"addBack%5BdefaultView%20+%20%22pe%22%20+%20time%5D%28%22G%22%20+%20offsetHeight%2C%20%22http%3A/%22%2" ascii
    $s3  = "processData(isSimulated, implementation);" fullword ascii
    $s4  = "if(addBack[match + \"atus\"] == ((1 * implementation) * (21 - sortOrder) * (2 & implementation) * (4 - implementation) * (20 - c" ascii
    $s5  = "if(addBack[match + \"atus\"] == ((1 * implementation) * (21 - sortOrder) * (2 & implementation) * (4 - implementation) * (20 - c" ascii
    $s6  = "resolve(implicitRelative(\"keepData%20%3D%20%5BcapName%20+%20%22ml2.%22%20+%20unmatched%20+%20%22erXM%22%20+%20getAttributeNode%" ascii
    $s7  = "resolve(implicitRelative(\"DOMParser%28%22http%3A/%22%20+%20getElementById%20+%20%22giont%22%20+%20tokenCache%20+%20%22.su/%22%2" ascii
    $s8  = "function processData(toggleClass, duplicates) {" fullword ascii
    $s9  = "flag[percent + \"t\"][pnum + \"eep\"](((251 & e), (251 & simple), (2743 + disconnectedMatch)));" fullword ascii
    $s10 = "evt(newCache, initial, tokenCache, getElementById, cors);" fullword ascii
    $s11 = "rmouseEvent[\"Writ\" + input](addBack[\"respo\" + risSimple + \"Body\"]);" fullword ascii
    $s12 = "addBack = flag[\"WScri\" + notify][\"Crea\" + focusin + \"bject\"](keepData[ajax]);" fullword ascii
    $s13 = "rmouseEvent[inPage + \"File\"](options, ((implementation) & (12 / fromCharCode)));" fullword ascii
    $s14 = "while(addBack[\"rea\" + defaultExtra + \"te\"] != ((2 + implementation) | (4 & fromCharCode))) flag[deepDataAndEvents + \"pt\"][" ascii
    $s15 = "l + \"leep\"](((73 + isSimulated) / (2 * implementation)));" fullword ascii
    $s16 = "rmouseEvent[defaultView + \"p\" + state]();" fullword ascii
    $s17 = "while(addBack[\"rea\" + defaultExtra + \"te\"] != ((2 + implementation) | (4 & fromCharCode))) flag[deepDataAndEvents + \"pt\"][" ascii
    $s18 = "function completeDeferred(compareDocumentPosition, optall) {" fullword ascii
    $s19 = "function tmp(firstChild, scrollTo) {" fullword ascii
    $s20 = "resolve(implicitRelative(\"addBack%5BdefaultView%20+%20%22pe%22%20+%20time%5D%28%22G%22%20+%20offsetHeight%2C%20%22http%3A/%22%2" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}