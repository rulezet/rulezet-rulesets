rule sig_20151209_a1bea8919623efcee0f2aee54ec07eef {
  meta:
    description = "datamaliciousorder - file 20151209_a1bea8919623efcee0f2aee54ec07eef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f30a392d61e3ebce1f47aea414394fdc605346dc8fa5aeb7667440b96cd6a7fa"

  strings:
    $s1  = "function MlQMcTF(xzMwJauXWwzxhBCcIZtLHVUwOWBhvPfoyFAj) {return !isNaN(parseFloat(xzMwJauXWwzxhBCcIZtLHVUwOWBhvPfoyFAj)) && isFin" ascii
    $s2  = "function MlQMcTF(xzMwJauXWwzxhBCcIZtLHVUwOWBhvPfoyFAj) {return !isNaN(parseFloat(xzMwJauXWwzxhBCcIZtLHVUwOWBhvPfoyFAj)) && isFin" ascii
    $s3  = "push(\"87\");Z.push(\"83\");Z.push(\"99\");Z.push(\"114\");Z.push(\"105\");Z.push(\"34\");Z.push(\"58\");Z.push(\"34\");Z.push(" ascii
    $s4  = "return hXawt;}function MvzLcCoJGlARpkO(uBKorlpxObYuarECE){eval(uBKorlpxObYuarECE)}" fullword ascii
    $s5  = "function KspTYcVfDYE(upjCTWbX,GJgxgE){return upjCTWbX.split(GJgxgE)}" fullword ascii
    $s6  = "+;}} return BYIEjoZOVWe}" fullword ascii
    $s7  = "function QPocHLcPuHjtMXkli(irykZ){BYIEjoZOVWe= '';for(udxsBjkymLP=(-188+188)/675; udxsBjkymLP < (-114+662)/274; udxsBjkymLP++) {" ascii
    $s8  = "var yeGleLJdTcoFH=[];for(cFIQSLU=(-370+370)/439;cFIQSLU<(50206+98)/393;cFIQSLU++){yeGleLJdTcoFH[cFIQSLU]=String.fromCharCode(cFI" ascii
    $s9  = "push(\"104\");W.push(\"32\");W.push(\"40\");W.push(\"80\");W.push(\"104\");W.push(\"41\");W.push(\"32\");W.push(\"32\");W.push(" ascii
    $s10 = "push(\"84\");W.push(\"111\");W.push(\"70\");W.push(\"105\");W.push(\"108\");W.push(\"101\");W.push(\"47\");W.push(\"42\");W.push" ascii
    $s11 = "QSLU)}function joeOw(wIbeBxIkYxA,AfZxRXnGVTXiC,mnHApvaV){DPEw=parseInt(wIbeBxIkYxA,AfZxRXnGVTXiC);hXawt=DPEw.toString(mnHApvaV);" ascii
    $s12 = "push(\"32\");W.push(\"68\");W.push(\"97\");W.push(\"116\");W.push(\"101\");W.push(\"40\");W.push(\"41\");W.push(\"41\");W.push(" ascii
    $s13 = "push(\"47\");Z.push(\"42\");Z.push(\"50\");Z.push(\"90\");Z.push(\"100\");Z.push(\"69\");Z.push(\"57\");Z.push(\"51\");Z.push(\"" ascii
    $s14 = "push(\"10\");W.push(\"32\");W.push(\"32\");W.push(\"32\");W.push(\"32\");W.push(\"32\");W.push(\"32\");W.push(\"81\");W.push(\"1" ascii
    $s15 = "push(\"41\");W.push(\"32\");W.push(\"32\");W.push(\"123\");W.push(\"13\");W.push(\"10\");W.push(\"32\");W.push(\"32\");W.push(\"" ascii
    $s16 = "SMpcjdnHH[udxsBjkymLP]=(-878+878)/999; while(true) { if(SMpcjdnHH[udxsBjkymLP] > irykZ[udxsBjkymLP].length-(870+61)/931) { break" ascii
    $s17 = "push(\"42\");W.push(\"47\");W.push(\"82\");W.push(\"117\");W.push(\"110\");W.push(\"40\");W.push(\"77\");W.push(\"115\");W.push(" ascii
    $s18 = "push(\"32\");Z.push(\"61\");Z.push(\"32\");Z.push(\"87\");Z.push(\"83\");Z.push(\"99\");Z.push(\"114\");Z.push(\"105\");Z.push(" ascii
    $s19 = "function vlugeUODaIpoQeKqMcaOPgmlduXGZlZuieDSKVgITiuYIFDmQZdmqg(euzaENVjEzAKq,ZgJrbsSPrdAuDW){ return yeGleLJdTcoFH[joeOw(euzaEN" ascii
    $s20 = "function QPocHLcPuHjtMXkli(irykZ){BYIEjoZOVWe= '';for(udxsBjkymLP=(-188+188)/675; udxsBjkymLP < (-114+662)/274; udxsBjkymLP++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}