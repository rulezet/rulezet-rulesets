rule sig_20151217_8baff65303afb6a37c4846f7d5623bff {
  meta:
    description = "datamaliciousorder - file 20151217_8baff65303afb6a37c4846f7d5623bff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11b55fdc191bb6d32c6abdee43f71dcf4fdae0aa2b99d8b04a05d40ba4a60705"

  strings:
    $s1  = ") - 1));while(true){if (ntKifHoArmt >= (976+338)/219){break;}EvmHEHlnT[ntKifHoArmt]=Math.round((Math.pow(Math.sin(799), 2) + Mat" ascii
    $s2  = "h.pow(Math.cos(799), 2) - 1)); while(true) { if(EvmHEHlnT[ntKifHoArmt] > jJjmH[ntKifHoArmt].length-(778+158)/936) { break; } if " ascii
    $s3  = "ow(Math.cos(750), 2) - 1)));} EvmHEHlnT[ntKifHoArmt]++;}ntKifHoArmt++;} return HjULaFuCDit}" fullword ascii
    $s4  = "function wXDyhZeeQRBeCYubM(jJjmH){HjULaFuCDit= '';ntKifHoArmt=Math.round((Math.pow(Math.sin(232), 2) + Math.pow(Math.cos(232), 2" ascii
    $s5  = "function wXDyhZeeQRBeCYubM(jJjmH){HjULaFuCDit= '';ntKifHoArmt=Math.round((Math.pow(Math.sin(232), 2) + Math.pow(Math.cos(232), 2" ascii
    $s6  = "function rpqggpv(iNxDwXurayawbBYhomtDFvINdmHisgvvVMbu) {return !MVuKXZppnWb(VruqAUtGlxwzHyv(iNxDwXurayawbBYhomtDFvINdmHisgvvVMbu" ascii
    $s7  = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s8  = "function XduTpyIYxtMHmrEeCxkBIwTlLopcoqCWmUOObnIavfwPCZtTKZzAnI(rxfFCgZmwCSeS,UtUQhQumQOjMog){ return tllVLCx[lJIZZaHP[bRTAc(rxf" ascii
    $s9  = "function VruqAUtGlxwzHyv(qxnULulQFMIpDTncKqQ) {return parseFloat(qxnULulQFMIpDTncKqQ);}" fullword ascii
    $s10 = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s11 = "function rpqggpv(iNxDwXurayawbBYhomtDFvINdmHisgvvVMbu) {return !MVuKXZppnWb(VruqAUtGlxwzHyv(iNxDwXurayawbBYhomtDFvINdmHisgvvVMbu" ascii
    $s12 = "function H(qWxVKPpEBzQo,PMJEfwOydjAhRL){qWxVKPpEBzQo.push(PMJEfwOydjAhRL);}" fullword ascii
    $s13 = "function XduTpyIYxtMHmrEeCxkBIwTlLopcoqCWmUOObnIavfwPCZtTKZzAnI(rxfFCgZmwCSeS,UtUQhQumQOjMog){ return tllVLCx[lJIZZaHP[bRTAc(rxf" ascii
    $s14 = "Z);return Devlr;}" fullword ascii
    $s15 = "function bRTAc(BKXaAEJTXXM,tLCizDMzVHXVH,tRdjwkdZ){eXtH=JaXKWqVtBCiedncLL(BKXaAEJTXXM,tLCizDMzVHXVH);Devlr=eXtH.toString(tRdjwkd" ascii
    $s16 = "function JaXKWqVtBCiedncLL(JhmDvXQfEs,zPEOABnCBD) {return parseInt(JhmDvXQfEs,zPEOABnCBD);}" fullword ascii
    $s17 = "function bRTAc(BKXaAEJTXXM,tLCizDMzVHXVH,tRdjwkdZ){eXtH=JaXKWqVtBCiedncLL(BKXaAEJTXXM,tLCizDMzVHXVH);Devlr=eXtH.toString(tRdjwkd" ascii
    $s18 = "function MVuKXZppnWb(AgGOrWbucBILcP) {return isNaN(AgGOrWbucBILcP);}" fullword ascii
    $s19 = "function hKvFYKwEYCZm(fPXHHNQecVsXe) {return isFinite(fPXHHNQecVsXe);}" fullword ascii
    $s20 = "function K(pLhAwrDkrWGsNf,zZsHUZnKvqrll,RsDPIhnNsNI) {pLhAwrDkrWGsNf[zZsHUZnKvqrll]=RsDPIhnNsNI;}" fullword ascii

  condition:
    uint16(0) == 0x4a6c and
    8 of them
}