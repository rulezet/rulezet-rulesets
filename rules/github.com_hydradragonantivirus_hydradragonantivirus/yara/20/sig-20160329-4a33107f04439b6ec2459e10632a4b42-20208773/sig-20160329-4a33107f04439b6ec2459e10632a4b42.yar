rule sig_20160329_4a33107f04439b6ec2459e10632a4b42 {
  meta:
    description = "datamaliciousorder - file 20160329_4a33107f04439b6ec2459e10632a4b42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "649758529e4ef420ebc1c021837f88a3c939e7a6ef0f03deb57f78bfef6382fd"

  strings:
    $s1  = "function rquickExpr(getWidthOrHeight, rcleanScript, eased) {" fullword ascii
    $s2  = "tweener[\"t\" + protocol + \"p\" + xhrSupported] = (1 & context);" fullword ascii
    $s3  = "        tweener[\"SaveT\" + easing](addGetHookIf, ((2 | resolveWith) + (0 & context)));" fullword ascii
    $s4  = "    createPositionalPseudo(\"expanded%5B%22o%22%20+%20mappedTypes%20+%20%22en%22%5D%28matchers%20+%20%22ET%22%2C%20rscriptType%2" ascii
    $s5  = "input(easing, buildParams, src, stopImmediatePropagation, computed);" fullword ascii
    $s6  = "    for(rfocusMorph = (0 | combinator); rfocusMorph < originalProperties[\"len\" + stopImmediatePropagation]; rfocusMorph++) {" fullword ascii
    $s7  = "    createPositionalPseudo(\"while%20%28expanded%5B%22readyS%22%20+%20memory%5D%20%21%3D%20%28%28push%29%7C%281+-context%29%29%2" ascii
    $s8  = "    createPositionalPseudo(\"expanded%5B%22o%22%20+%20mappedTypes%20+%20%22en%22%5D%28matchers%20+%20%22ET%22%2C%20rscriptType%2" ascii
    $s9  = "function animated() {" fullword ascii
    $s10 = "fast();" fullword ascii
    $s11 = "function fast() {" fullword ascii
    $s12 = "function prevUntil() {" fullword ascii
    $s13 = "function setter() {" fullword ascii
    $s14 = "pointerenter(unique);" fullword ascii
    $s15 = "        rnoContent[left + \"ript\"][state](((113208 & pixelMarginRight) / (131, callback)));" fullword ascii
    $s16 = "function selectedIndex(dest) {" fullword ascii
    $s17 = "function createPositionalPseudo(risSimple) {" fullword ascii
    $s18 = "function input(arr, rdashAlpha, self) {" fullword ascii
    $s19 = "function pointerenter(currentTime, simple) {" fullword ascii
    $s20 = "function nextAll(offsetParent, cloneCopyEvent) {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}