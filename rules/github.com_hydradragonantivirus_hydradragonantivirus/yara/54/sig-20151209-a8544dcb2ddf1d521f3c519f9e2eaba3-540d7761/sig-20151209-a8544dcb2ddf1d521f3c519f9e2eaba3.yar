rule sig_20151209_a8544dcb2ddf1d521f3c519f9e2eaba3 {
  meta:
    description = "datamaliciousorder - file 20151209_a8544dcb2ddf1d521f3c519f9e2eaba3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956deae6b70e3060f17c40b9129c7c70c077032beac1419a1155db863e740b21"

  strings:
    $s1  = "function PkFBXncRqZLkNfCOM(XeCMY){IPfBSVEdJaD= '';for(lMzERejpAvg=(-495+495)/398; lMzERejpAvg < (258+534)/396; lMzERejpAvg++) {R" ascii
    $s2  = "function nsVOzWT(AyhMPYmEBSBBKMXHCHaGZWqklCztzRQuXlHP) {return !isNaN(parseFloat(AyhMPYmEBSBBKMXHCHaGZWqklCztzRQuXlHP)) && isFin" ascii
    $s3  = "function PkFBXncRqZLkNfCOM(XeCMY){IPfBSVEdJaD= '';for(lMzERejpAvg=(-495+495)/398; lMzERejpAvg < (258+534)/396; lMzERejpAvg++) {R" ascii
    $s4  = "function nsVOzWT(AyhMPYmEBSBBKMXHCHaGZWqklCztzRQuXlHP) {return !isNaN(parseFloat(AyhMPYmEBSBBKMXHCHaGZWqklCztzRQuXlHP)) && isFin" ascii
    $s5  = " weuXH;}function mpXGdLRzHjAXTyZ(IUZXiUUsigHHQIdrD){eval(IUZXiUUsigHHQIdrD)}" fullword ascii
    $s6  = "function OnBFHvseGYn(NGaTbMIc,txalFc){return NGaTbMIc.split(txalFc)}" fullword ascii
    $s7  = "'m';NETia[110]='n';NETia[111]='o';NETia[112]='p';NETia[113]='q';NETia[114]='r';NETia[115]='s';NETia[116]='t';NETia[117]='u';NETi" ascii
    $s8  = "function zyAjQ(EiqDVBNHfaJ,CgByAMXczhEzk,BXiJVeqc){pVbr=parseInt(EiqDVBNHfaJ,CgByAMXczhEzk);weuXH=pVbr.toString(BXiJVeqc);return" ascii
    $s9  = "}} return IPfBSVEdJaD}" fullword ascii
    $s10 = "function zyAjQ(EiqDVBNHfaJ,CgByAMXczhEzk,BXiJVeqc){pVbr=parseInt(EiqDVBNHfaJ,CgByAMXczhEzk);weuXH=pVbr.toString(BXiJVeqc);return" ascii
    $s11 = "wUxhzrhg[lMzERejpAvg]=(-434+434)/934; while(true) { if(RwUxhzrhg[lMzERejpAvg] > XeCMY[lMzERejpAvg].length-(552+109)/661) { break" ascii
    $s12 = "function KhsfflPRLvPbLZwnqFxRgbvCCUofNGFSllIXupdeSdyhVhJCXyfzZO(njQSWdmcaEdiI,SFJLLnPkDXOTmt){ return NETia[zyAjQ(njQSWdmcaEdiI[" ascii
    $s13 = "function KhsfflPRLvPbLZwnqFxRgbvCCUofNGFSllIXupdeSdyhVhJCXyfzZO(njQSWdmcaEdiI,SFJLLnPkDXOTmt){ return NETia[zyAjQ(njQSWdmcaEdiI[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}