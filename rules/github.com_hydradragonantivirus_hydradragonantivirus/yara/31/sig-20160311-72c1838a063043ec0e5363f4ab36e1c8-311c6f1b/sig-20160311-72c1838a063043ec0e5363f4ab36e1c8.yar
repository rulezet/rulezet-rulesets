rule sig_20160311_72c1838a063043ec0e5363f4ab36e1c8 {
  meta:
    description = "datamaliciousorder - file 20160311_72c1838a063043ec0e5363f4ab36e1c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8788ed3bae4789f0ae8d5b0224ea83382ec9402a4a41816b0c604a34089d8fd"

  strings:
    $x1  = "name[newUnmatched + \"en\"](contexts + \"E\" + eased, \"http:\".state() + elementMatchers + \"ww.\" + preferredDoc + \"stav.\" +" ascii
    $s2  = "round = locked[\"Expand\" + cssExpand + \"onm\".state() + animation + \"ing\" + doc](\"%TEMP\" + rmargin) + \"getEl\".state() + " ascii
    $s3  = "ndChild))), (((1 * image) + (Math.pow(1675, image) - 2803537)) / (pixelPosition - 48) * (sourceIndex | 3)), (toggle, 3) * ((getW" ascii
    $s4  = "round = locked[\"Expand\" + cssExpand + \"onm\".state() + animation + \"ing\" + doc](\"%TEMP\" + rmargin) + \"getEl\".state() + " ascii
    $s5  = "camelCase[\"t\" + l + \"e\".state()] = ((getScript - 63) - (truncate + 1));" fullword ascii
    $s6  = "lements)), (((478 + arr) - (734 & contentDocument)) / ((329 * t + 70) / (undelegate * 3 + apply))))) > 8));" fullword ascii
    $s7  = "name[newUnmatched + \"en\"](contexts + \"E\" + eased, \"http:\".state() + elementMatchers + \"ww.\" + preferredDoc + \"stav.\" +" ascii
    $s8  = "off = (((4 * setRequestHeader + 3) + (responseHeadersString - 90)), ((t & 5) + image * 2 * setRequestHeader), eval(\"t\" + statu" ascii
    $s9  = "off = (((4 * setRequestHeader + 3) + (responseHeadersString - 90)), ((t & 5) + image * 2 * setRequestHeader), eval(\"t\" + statu" ascii
    $s10 = "(prependTo - 23)), (setRequestHeader * 2 * image * 2 * image * 2 / image * 3 * image * 2)) | (((DOMParser - 42) & (visibility, 3" ascii
    $s11 = ")) + (apply + (8 | image)))) & ((((13 & refElements) + (49 - boxSizingReliable)) | ((36 * image + 31) + (Math.pow(qsa, 2) - appe" ascii
    $s12 = "name = off[addCombinator + \"t\".state()][conv2 + \"Object\"](responses + \".XML\" + rmultiDash + \"P\".state());" fullword ascii
    $s13 = "locked = rprotocol[divStyle + \"teObj\" + write](\"WScr\".state() + Expr + \"Shel\" + getStyles);" fullword ascii
    $s14 = "Prevented + \"/08\".state() + fixInput + \"7\", !(((((5 * image + (4752 / promise)), (139 - (innerText * 6 + createTextNode)), (" ascii
    $s15 = "name[rtrim + \"nd\"]();" fullword ascii
    $s16 = "rprotocol = off[factory + \"pt\"];" fullword ascii
    $s17 = "not[pointerenter + \"pe\" + protocol]();" fullword ascii
    $s18 = "function accepts() {" fullword ascii
    $s19 = "function code() {" fullword ascii
    $s20 = "toggle = 65," fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}