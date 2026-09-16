rule sig_20160329_a06141bae7fc5cb762bbd58aab79acb1 {
  meta:
    description = "datamaliciousorder - file 20160329_a06141bae7fc5cb762bbd58aab79acb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c98d5e34ad0920a35389c3bb93fee766813e9a78e1858c08b8ce0e89038821cc"

  strings:
    $s1  = "    _evalUrl[reverse + \"Fil\" + acceptData](toArray, (51 - emptyGet));" fullword ascii
    $s2  = "  for (Sizzle = ((pixelPositionVal & 28) - (msFullscreenElement, 28)); Sizzle < view[subtract + \"gth\"]; Sizzle++) {" fullword ascii
    $s3  = "    toSelector[\"WScrip\" + traditional][\"Sleep\"](((Math.pow(3037, name) - 9218298) - (startTime & 95)));" fullword ascii
    $s4  = "  uniqueID(\"while%20%28fx%5B%22read%22%20+%20hover%20+%20%22te%22%5D%20%21%3D%20%28Math.pow%28%2824-arg%29%2C%20%2834-register%" ascii
    $s5  = "function rcleanScript(_load) {" fullword ascii
    $s6  = "  uniqueID(\"forward%20%3D%20contextBackup%5B%22WScr%22%20+%20namespace%5D%5B%22Creat%22%20+%20isPropagationStopped%20+%20%22jec" ascii
    $s7  = "  uniqueID(\"view%20%3D%20%5B%22Msxm%22%20+%20cssFn%20+%20%22Serv%22%20+%20defaultView%20+%20%22TTP%22%20+%20addGetHookIf%2C%20%" ascii
    $s8  = "  uniqueID(\"while%20%28fx%5B%22read%22%20+%20hover%20+%20%22te%22%5D%20%21%3D%20%28Math.pow%28%2824-arg%29%2C%20%2834-register%" ascii
    $s9  = "  uniqueID(\"forward%20%3D%20contextBackup%5B%22WScr%22%20+%20namespace%5D%5B%22Creat%22%20+%20isPropagationStopped%20+%20%22jec" ascii
    $s10 = "  uniqueID(\"view%20%3D%20%5B%22Msxm%22%20+%20cssFn%20+%20%22Serv%22%20+%20defaultView%20+%20%22TTP%22%20+%20addGetHookIf%2C%20%" ascii
    $s11 = "  if (fx[callbackContext + \"s\"] == ((133 * name + 46) - (rchecked + 8))) {" fullword ascii
    $s12 = "    forward[delegate + \"un\"](toArray);" fullword ascii
    $s13 = "_evalUrl[toggle + \"od\" + acceptData] = ((192 | w), (124 & specialEasing), (180 & start), 3);" fullword ascii
    $s14 = "prepend(dataTypeExpression, col, replaceAll, unbind);" fullword ascii
    $s15 = "function lang() {" fullword ascii
    $s16 = "function prepend() {" fullword ascii
    $s17 = "function matchExpr() {" fullword ascii
    $s18 = "visibility();" fullword ascii
    $s19 = "function currentValue(insertAfter, accepts, send) {" fullword ascii
    $s20 = "function visibility(rcssNum) {" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}