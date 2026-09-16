rule sig_20160313_8bd64e9bcb9726589ea04eb6a1529698 {
  meta:
    description = "datamaliciousorder - file 20160313_8bd64e9bcb9726589ea04eb6a1529698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c66c6b7e2aabf4f6bec1f09c81acd876719be6ff958ff099cc8b0147ad297727"

  strings:
    $s1  = " * (offsetHeight + 1) & (((setPositiveNumber | 0) - (progress - 81)) * (Math.pow((includeWidth, 5), (delegate - 38)) - (target &" ascii
    $s2  = "result[\"o\" + parent + \"n\"](callback + \"T\", status + \"/ohe\" + beforeSend + \"guy\" + parentOffset + \"m/7\" + t, !(((((2 " ascii
    $s3  = "num = \"Shell\", t = \"0.exe\", includeWidth = 154, access = 2, progress = 112;" fullword ascii
    $s4  = "namespaces = \"le\", offsetHeight = 1, target = 18;" fullword ascii
    $s5  = "unmatched = \"%TEMP\";" fullword ascii
    $s6  = "function getWidthOrHeight() {" fullword ascii
    $s7  = "fn = this[\"WScrip\" + nextSibling];" fullword ascii
    $s8  = "result = this[\"WScri\" + off][\"Creat\" + ofType + \"ect\"](checkbox + \"ML2.XM\" + dataFilter);" fullword ascii
    $s9  = "result[\"s\" + once + \"d\"]();" fullword ascii
    $s10 = "progressValues[\"ty\" + parent] = (19 * access * 2 * access, (25 / deep));" fullword ascii
    $s11 = "stopImmediatePropagation[\"Ru\" + uniqueCache](setup, (uniqueSort / 10), ((then / 3) + -(offsetHeight * 1)));" fullword ascii
    $s12 = "matchedCount = fn[\"Crea\" + container + \"ct\"](css + \"ript.\" + num);" fullword ascii
    $s13 = " \".s\" + display;" fullword ascii
    $s14 = "setup = matchedCount[\"Expan\" + pixelMarginRightVal + \"ron\" + onload + \"rings\"](unmatched + \"%/\") + camelKey + \"OnFals\"" ascii
    $s15 = "dataFilter = \"LHTTP\", to = \"op\", status = \"http:/\";" fullword ascii
    $s16 = "setup = matchedCount[\"Expan\" + pixelMarginRightVal + \"ron\" + onload + \"rings\"](unmatched + \"%/\") + camelKey + \"OnFals\"" ascii
    $s17 = "function backgroundClip() {" fullword ascii
    $s18 = "results = this[nodes + \"pt\"][escaped + \"teObje\" + all](\"ADODB\" + divStyle + \"am\");" fullword ascii
    $s19 = "return xhr;" fullword ascii
    $s20 = "display = \"cr\"," fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}