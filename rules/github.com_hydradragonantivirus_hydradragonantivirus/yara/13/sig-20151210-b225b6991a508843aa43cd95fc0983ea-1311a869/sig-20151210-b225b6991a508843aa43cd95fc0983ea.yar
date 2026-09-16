rule sig_20151210_b225b6991a508843aa43cd95fc0983ea {
  meta:
    description = "datamaliciousorder - file 20151210_b225b6991a508843aa43cd95fc0983ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f629977a0ea5b7a4145b280fd8adb37a20c3354ad56520682f5bc055c07397b"

  strings:
    $s1  = "function XDRenGh(lysScVeMsatmbKLAuuYZzWoGnCuMPcEBaRkZ) {return !isNaN(parseFloat(lysScVeMsatmbKLAuuYZzWoGnCuMPcEBaRkZ)) && isFin" ascii
    $s2  = "function XDRenGh(lysScVeMsatmbKLAuuYZzWoGnCuMPcEBaRkZ) {return !isNaN(parseFloat(lysScVeMsatmbKLAuuYZzWoGnCuMPcEBaRkZ)) && isFin" ascii
    $s3  = "coWypvjf[iBADiMgRBIk]=(-720+720)/477; while(true) { if(scoWypvjf[iBADiMgRBIk] > PuBUL[iBADiMgRBIk].length-(62+109)/171) { break;" ascii
    $s4  = "SJDDoij=(-527+527)/440;while(true){if(SJDDoij>=(303+465)/6){break;}vhqUNDARmIeNi[SJDDoij]=String.fromCharCode(SJDDoij);SJDDoij++" ascii
    $s5  = "+;}} return VnLKtOjVkta}" fullword ascii
    $s6  = "function omQJc(hAmTwImdFnF,nqqFwHLoOFebZ,RluDuwIz){jXOE=parseInt(hAmTwImdFnF,nqqFwHLoOFebZ);ectjO=jXOE.toString(RluDuwIz);return" ascii
    $s7  = "function pdrgmPcUDbeDQwdYGPwvFBDcFeXsRjiedVGfQblvFtskapltPGwEmn(OENsTrkwtucoO,elcZaGzjRjZlJl){ return vhqUNDARmIeNi[omQJc(OENsTr" ascii
    $s8  = "function omQJc(hAmTwImdFnF,nqqFwHLoOFebZ,RluDuwIz){jXOE=parseInt(hAmTwImdFnF,nqqFwHLoOFebZ);ectjO=jXOE.toString(RluDuwIz);return" ascii
    $s9  = "function WtSVnrSwMGtmNAAHd(PuBUL){VnLKtOjVkta= '';for(iBADiMgRBIk=(-266+266)/147; iBADiMgRBIk < (435+921)/678; iBADiMgRBIk++) {s" ascii
    $s10 = "function pdrgmPcUDbeDQwdYGPwvFBDcFeXsRjiedVGfQblvFtskapltPGwEmn(OENsTrkwtucoO,elcZaGzjRjZlJl){ return vhqUNDARmIeNi[omQJc(OENsTr" ascii
    $s11 = "SJDDoij=(-527+527)/440;while(true){if(SJDDoij>=(303+465)/6){break;}vhqUNDARmIeNi[SJDDoij]=String.fromCharCode(SJDDoij);SJDDoij++" ascii
    $s12 = "function EbMXaVHganC(DYdVKYmR,wyEUyS){return DYdVKYmR.split(wyEUyS)}" fullword ascii
    $s13 = "function WtSVnrSwMGtmNAAHd(PuBUL){VnLKtOjVkta= '';for(iBADiMgRBIk=(-266+266)/147; iBADiMgRBIk < (435+921)/678; iBADiMgRBIk++) {s" ascii
    $s14 = " ectjO;}function MXhwpmYAlFRadsG(zuTpjOENnzTzhXeVf){eval(zuTpjOENnzTzhXeVf)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}