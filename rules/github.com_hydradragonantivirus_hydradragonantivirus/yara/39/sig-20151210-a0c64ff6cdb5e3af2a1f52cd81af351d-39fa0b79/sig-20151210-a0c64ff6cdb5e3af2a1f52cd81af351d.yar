rule sig_20151210_a0c64ff6cdb5e3af2a1f52cd81af351d {
  meta:
    description = "datamaliciousorder - file 20151210_a0c64ff6cdb5e3af2a1f52cd81af351d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "711630ca31433c569d0e4b73607a6a0f7db916f1164e4408b7052a7f67f9f672"

  strings:
    $s1  = "function qDEdxPF(tTEgGneXIJtEycTpLmSPMZiBkWZAIkGPylJG) {return !isNaN(parseFloat(tTEgGneXIJtEycTpLmSPMZiBkWZAIkGPylJG)) && isFin" ascii
    $s2  = "function qDEdxPF(tTEgGneXIJtEycTpLmSPMZiBkWZAIkGPylJG) {return !isNaN(parseFloat(tTEgGneXIJtEycTpLmSPMZiBkWZAIkGPylJG)) && isFin" ascii
    $s3  = "function tpTzF(QwumFuINRPq,LEIpbuKoANbIc,wxblcXJJ){BrkX=parseInt(QwumFuINRPq,LEIpbuKoANbIc);LTwVH=BrkX.toString(wxblcXJJ);return" ascii
    $s4  = "function JjNIlSOejow(hoYFemVi,LBUETG){return hoYFemVi.split(LBUETG)}" fullword ascii
    $s5  = "dyyGcVX=(-208+208)/365;while(true){if(dyyGcVX>=(115497+87)/903){break;}QxtgzTGNfKtkk[dyyGcVX]=String.fromCharCode(dyyGcVX);dyyGc" ascii
    $s6  = "dyyGcVX=(-208+208)/365;while(true){if(dyyGcVX>=(115497+87)/903){break;}QxtgzTGNfKtkk[dyyGcVX]=String.fromCharCode(dyyGcVX);dyyGc" ascii
    $s7  = ";}} return wfZXOSJxEuC}" fullword ascii
    $s8  = "sNZKY[mZElwaRxTPZ]=(-598+598)/941; while(true) { if(RZspsNZKY[mZElwaRxTPZ] > avhbs[mZElwaRxTPZ].length-(-375+653)/278) { break; " ascii
    $s9  = "function iSmnxgNjepbmXIfxvWxesCgFPmGCgDwjeUBqldDzIYFijrGHCauMrQ(dfCAxqUlCPMSc,zaqNiYtsaepSrv){ return QxtgzTGNfKtkk[tpTzF(dfCAxq" ascii
    $s10 = "function iSmnxgNjepbmXIfxvWxesCgFPmGCgDwjeUBqldDzIYFijrGHCauMrQ(dfCAxqUlCPMSc,zaqNiYtsaepSrv){ return QxtgzTGNfKtkk[tpTzF(dfCAxq" ascii
    $s11 = " LTwVH;}function IBSWpBWAjtPfhoz(SPVHkWndSQcAStrqZ){eval(SPVHkWndSQcAStrqZ)}" fullword ascii
    $s12 = "function CjBCAmWWvOFMTmFVK(avhbs){wfZXOSJxEuC= '';for(mZElwaRxTPZ=(-25+25)/908; mZElwaRxTPZ < (40+784)/412; mZElwaRxTPZ++) {RZsp" ascii
    $s13 = "function CjBCAmWWvOFMTmFVK(avhbs){wfZXOSJxEuC= '';for(mZElwaRxTPZ=(-25+25)/908; mZElwaRxTPZ < (40+784)/412; mZElwaRxTPZ++) {RZsp" ascii
    $s14 = "function tpTzF(QwumFuINRPq,LEIpbuKoANbIc,wxblcXJJ){BrkX=parseInt(QwumFuINRPq,LEIpbuKoANbIc);LTwVH=BrkX.toString(wxblcXJJ);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}