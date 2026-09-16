rule sig_20160301_4b22cc6e8102e2d2c2189376c7208f20 {
  meta:
    description = "datamaliciousorder - file 20160301_4b22cc6e8102e2d2c2189376c7208f20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59eafc7cfd1174b203712e219fd68ddd13c31b2e291b5c4ae7a977c3bb974325"

  strings:
    $s1 = "manifestRisk[(\"\\u0069l\\u006c\\u0065ga\" + \"\\u006c\", function String.prototype.deformationComplex() {" fullword ascii
    $s2 = "while(coordinationApparatus[(\"\\u0073p\" + \"her\" + \"e\", \"\\u0072\\u0068o\\u006d\" + \"bu\\u0073\", \"ac\\u0061\\u0064e\" +" ascii
    $s3 = "while(coordinationApparatus[(\"\\u0073p\" + \"her\" + \"e\", \"\\u0072\\u0068o\\u006d\" + \"bu\\u0073\", \"ac\\u0061\\u0064e\" +" ascii
    $s4 = "diagramMaximum = (((1 & 1)), this);" fullword ascii
    $s5 = "} catch(tunnelMark) {};" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}