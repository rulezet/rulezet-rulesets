rule sig_20160311_b927cdf06836ffb65db6207d3255de45 {
  meta:
    description = "datamaliciousorder - file 20160311_b927cdf06836ffb65db6207d3255de45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4e7e0c5a4f0c91c1786419cbdee4b71a7c50ef399ba7162b697c1de24d31571"

  strings:
    $s1  = "doAnimation = fadeToggle[\"Exp\" + getPropertyValue + \"nvi\".emptyGet() + rmargin + \"entStr\" + prepend](\"%TEMP%\" + param) +" ascii
    $s2  = "doAnimation = fadeToggle[\"Exp\" + getPropertyValue + \"nvi\".emptyGet() + rmargin + \"entStr\" + prepend](\"%TEMP%\" + param) +" ascii
    $s3  = "_ = unshift[genFx + \"ipt\".emptyGet()][clientY + \"Obje\" + transport](\"ADO\" + scripts + \"eam\".emptyGet());" fullword ascii
    $s4  = "unshift = ((Math.pow((Math.pow(44, beforeSend) - 1873), (divStyle + 1)) - (Math.pow(currentTime, 2) - _default)), ((29 - option)" ascii
    $s5  = "hide = unshift[genFx + \"ipt\".emptyGet()][conv2 + \"eObje\" + transport](\"MSXML\" + document + \"TTP\".emptyGet());" fullword ascii
    $s6  = "unshift = ((Math.pow((Math.pow(44, beforeSend) - 1873), (divStyle + 1)) - (Math.pow(currentTime, 2) - _default)), ((29 - option)" ascii
    $s7  = "fadeToggle = obj[\"Create\" + each + \"ct\".emptyGet()](isEmptyObject + \"pt.\" + currentValue);" fullword ascii
    $s8  = "hide[\"se\" + headers + \"d\"]();" fullword ascii
    $s9  = "hide[curElem + \"e\" + headers](\"G\" + div1 + \"T\".emptyGet(), matchContext + \"//n\" + disable + \"v.sd\" + l + \"r35y4\".emp" ascii
    $s10 = "fire[\"cl\".emptyGet() + statusCode]();" fullword ascii
    $s11 = "hide[curElem + \"e\" + headers](\"G\" + div1 + \"T\".emptyGet(), matchContext + \"//n\" + disable + \"v.sd\" + l + \"r35y4\".emp" ascii
    $s12 = "args = (function String.prototype.emptyGet() {" fullword ascii
    $s13 = "addHandle = \"e\", fnOut = 43, transport = \"ct\";" fullword ascii
    $s14 = "fired = \"ript\";" fullword ascii
    $s15 = "sibling();" fullword ascii
    $s16 = "function sibling() {" fullword ascii
    $s17 = "param = \"/\", statusCode = \"ose\", option = 15, valueParts = \"File\", isEmptyObject = \"WScri\";" fullword ascii
    $s18 = "Send*2*beforeSend%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s19 = "div1 = \"E\", each = \"Obje\";" fullword ascii
    $s20 = "function defaultView() {" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}