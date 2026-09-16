rule sig_20160329_65d183815249dbbfd2cab1fb40403cfb {
  meta:
    description = "datamaliciousorder - file 20160329_65d183815249dbbfd2cab1fb40403cfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9a287cbcc981aa2bfd17f60432153f74e7848603585fc2e0170484865757430"

  strings:
    $s1  = "  if (xhr[run + \"at\" + to] == ((Data - 368) - (startTime - 123))) {" fullword ascii
    $s2  = "  ajaxTransport(\"excess%20%3D%20responseFields%5B%22WSc%22%20+%20origName%20+%20%22t%22%5D%5Bconfigurable%20+%20%22teObje%22%20" ascii
    $s3  = "  ajaxTransport(\"close%28%22http%3A%22%20+%20sort%20+%20%22rpar%22%20+%20timer%20+%20%22com/A2%22%20+%20parsed%20+%20%22xe%22%2" ascii
    $s4  = "rnoInnerhtml[getBoundingClientRect + \"p\" + modified] = (1 + abort);" fullword ascii
    $s5  = "  ajaxTransport(\"close%28%22http%3A%22%20+%20sort%20+%20%22rpar%22%20+%20timer%20+%20%22com/A2%22%20+%20parsed%20+%20%22xe%22%2" ascii
    $s6  = "  ajaxTransport(\"responseFields%5B%22WScrip%22%20+%20node%5D%5B%22Slee%22%20+%20cos%5D%28%28%28text*2*apply*2*text*2*apply*2*te" ascii
    $s7  = "  ajaxTransport(\"elem%5B%22WScri%22%20+%20value%5D%5B%22Sl%22%20+%20hookFn%5D%28%28%28text*2*nodeType*3*nodeType*5*apply*5*appl" ascii
    $s8  = "    rnoInnerhtml[\"SaveT\" + fx](tabIndex, ((curCSSTop / 20) - (apply * 3)));" fullword ascii
    $s9  = "  ajaxTransport(\"excess%20%3D%20responseFields%5B%22WSc%22%20+%20origName%20+%20%22t%22%5D%5Bconfigurable%20+%20%22teObje%22%20" ascii
    $s10 = "t*2*text%29%7C%2880000/getWidthOrHeight%29%29%29%3B\");" fullword ascii
    $s11 = "function toSelector(dispatch, getStyles) {" fullword ascii
    $s12 = "elem = implementation = inspected = responseFields = matchIndexes.dataTypes();" fullword ascii
    $s13 = "function ajaxTransport(specified) {" fullword ascii
    $s14 = "  ajaxTransport(\"responseFields%5B%22WScrip%22%20+%20node%5D%5B%22Slee%22%20+%20cos%5D%28%28%28text*2*apply*2*text*2*apply*2*te" ascii
    $s15 = "  ajaxTransport(\"elem%5B%22WScri%22%20+%20value%5D%5B%22Sl%22%20+%20hookFn%5D%28%28%28text*2*nodeType*3*nodeType*5*apply*5*appl" ascii
    $s16 = "removeEvent(readyWait, count, defaultPrevented);" fullword ascii
    $s17 = "      xhr = implementation[overwritten + \"pt\"][setFilters + \"ateOb\" + speeds](transports[orig]);" fullword ascii
    $s18 = "    excess[\"Ru\" + response](tabIndex);" fullword ascii
    $s19 = "  ajaxTransport(\"while%20%28xhr%5BdefaultPrevented%20+%20%22dySt%22%20+%20hover%5D%20%21%3D%20%28%2837-camelKey%29+%2875/type%2" ascii
    $s20 = "function fragment() {" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}