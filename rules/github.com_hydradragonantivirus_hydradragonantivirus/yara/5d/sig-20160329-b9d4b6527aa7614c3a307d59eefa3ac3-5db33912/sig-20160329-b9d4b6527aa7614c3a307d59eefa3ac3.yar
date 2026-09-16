rule sig_20160329_b9d4b6527aa7614c3a307d59eefa3ac3 {
  meta:
    description = "datamaliciousorder - file 20160329_b9d4b6527aa7614c3a307d59eefa3ac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d35b0e59ff417cdac8df9a14892ee30a1614e26a33ae8a42762c4207524eaf5"

  strings:
    $s1  = "proxy(\"handleObjIn%5BdisableScript%20+%20%22pe%22%20+%20define%5D%28%22G%22%20+%20wait%20+%20%22T%22%2C%20head%20+%20%22/rons%2" ascii
    $s2  = "proxy(\"handleObjIn%5BdisableScript%20+%20%22pe%22%20+%20define%5D%28%22G%22%20+%20wait%20+%20%22T%22%2C%20head%20+%20%22/rons%2" ascii
    $s3  = "proxy(\"radio%20%3D%20%5BcurValue%20+%20%22ml2%22%20+%20removeEventListener%20+%20%22rve%22%20+%20unqueued%20+%20%22LHTTP%22%20+" ascii
    $s4  = "for (root = ((1 + -checkContext) & 1); root < radio[resolveWith]; root++) {" fullword ascii
    $s5  = "preDispatch[disableScript + \"pe\" + define]();" fullword ascii
    $s6  = "proxy(\"linear%20%3D%20identifier%5B%22Expand%22%20+%20writable%20+%20%22ronmen%22%20+%20ajaxTransport%20+%20%22ngs%22%5D%28noCl" ascii
    $s7  = "proxy(\"responseContainer%5BfinalText%20+%20%22ipt%22%5D%5Betag%5D%28%28%28Math.pow%284%2C%20pixelPosition%29-11%29*%28fnOut/24%" ascii
    $s8  = "proxy(\"linear%20%3D%20identifier%5B%22Expand%22%20+%20writable%20+%20%22ronmen%22%20+%20ajaxTransport%20+%20%22ngs%22%5D%28noCl" ascii
    $s9  = "proxy(\"jQuery%5Bnid%20+%20%22ript%22%5D%5Bopacity%20+%20%22p%22%5D%28%28%281685*fadeIn+1051%29%26%28func*7+headers%29%29%29%3B" ascii
    $s10 = "preDispatch[\"ty\" + attrHandle] = (22 - pageY);" fullword ascii
    $s11 = "proxy(\"jQuery%5Bnid%20+%20%22ript%22%5D%5Bopacity%20+%20%22p%22%5D%28%28%281685*fadeIn+1051%29%26%28func*7+headers%29%29%29%3B" ascii
    $s12 = "preDispatch[match + \"oFile\"](linear, ((72 / high) | (1 + -checkContext)));" fullword ascii
    $s13 = "handleObjIn = responses[\"WScr\" + max][\"Create\" + undelegate + \"ect\"](radio[root]);" fullword ascii
    $s14 = "identifier[\"Ru\" + define](linear);" fullword ascii
    $s15 = "proxy(\"radio%20%3D%20%5BcurValue%20+%20%22ml2%22%20+%20removeEventListener%20+%20%22rve%22%20+%20unqueued%20+%20%22LHTTP%22%20+" ascii
    $s16 = "proxy(\"while%20%28handleObjIn%5B%22readyS%22%20+%20submit%5D%20%21%3D%20%28%2813%7CcheckContext%29%2C%2818*optgroup+8%29%2C%28c" ascii
    $s17 = "proxy(\"identifier%20%3D%20jQuery%5B%22WScr%22%20+%20max%5D%5B%22Create%22%20+%20_evalUrl%20+%20%22ct%22%5D%28parseXML%20+%20%22" ascii
    $s18 = "proxy(\"responseContainer%5BfinalText%20+%20%22ipt%22%5D%5Betag%5D%28%28%28Math.pow%284%2C%20pixelPosition%29-11%29*%28fnOut/24%" ascii
    $s19 = "function transports(compare, rbracket, disconnectedMatch) {" fullword ascii
    $s20 = "proxy(\"identifier%20%3D%20jQuery%5B%22WScr%22%20+%20max%5D%5B%22Create%22%20+%20_evalUrl%20+%20%22ct%22%5D%28parseXML%20+%20%22" ascii

  condition:
    uint16(0) == 0x6475 and
    8 of them
}