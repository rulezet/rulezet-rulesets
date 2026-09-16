rule sig_20160311_6aa495dd235e376a7924434726822a43 {
  meta:
    description = "datamaliciousorder - file 20160311_6aa495dd235e376a7924434726822a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c28e7379901a01fd678a8439cc3a384aec4a7df02b9af7c603ca2aaee829a528"

  strings:
    $s1  = "fadeToggle = (((3969 / relative) & (116 * inPage + 45)), ((Math.pow(finalDataType, 2) - rootjQuery) - (Math.pow(9, inPage) - 65)" ascii
    $s2  = "implicitRelative[\"op\".rcombinators() + n + \"n\"](headers + \"T\", e + \"/thaih\".rcombinators() + responseType + \".biz/\" + " ascii
    $s3  = "fadeToggle = (((3969 / relative) & (116 * inPage + 45)), ((Math.pow(finalDataType, 2) - rootjQuery) - (Math.pow(9, inPage) - 65)" ascii
    $s4  = "ow(hold, 2) - bool))), (((48 / next) * 0) / ((attr, 169, completeDeferred, 2) | (sort, 41)))) | ((cssProps * 3) * (chainable - 2" ascii
    $s5  = "ionVal + \"yletha\" + suffix + \"om/43t\".rcombinators() + col, !(((emptyStyle / 42) | (emptyStyle | 2)) == ((((success & 105) -" ascii
    $s6  = "function rkeyEvent() {" fullword ascii
    $s7  = ") * inPage * (1 * inPage) * (2 & inPage) - ((142 & triggerHandler) - (46 + next))))));" fullword ascii
    $s8  = "th.pow(structure, 2) - domManip)), (Math.pow((2 * (caption / 12)), ((cssProps + 0) * (subordinate, 41, inPage))) - (19 + (Math.p" ascii
    $s9  = "implicitRelative = fadeToggle[\"WScr\" + animate][\"Creat\".rcombinators() + condense + \"t\"](parseFromString + \"2.XM\" + unti" ascii
    $s10 = "duration = getElementsByName;" fullword ascii
    $s11 = "duration[defaultView + \"se\"]();" fullword ascii
    $s12 = "n = (function String.prototype.rcombinators() {" fullword ascii
    $s13 = "condense = \"eObjec\", fx = \"wri\", createHTMLDocument = \"pt.\", domManip = 551, username = \"se\", sort = 247;" fullword ascii
    $s14 = "var until = \"LHTTP\"," fullword ascii
    $s15 = "return after" fullword ascii
    $s16 = "resolve = \"WScri\";" fullword ascii
    $s17 = "function raw() {" fullword ascii
    $s18 = "var after = this;" fullword ascii
    $s19 = "animate = \"ipt\";" fullword ascii
    $s20 = "var bool = 18," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}