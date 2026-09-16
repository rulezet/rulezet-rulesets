rule sig_20151208_9dd4633f23abe0230bc4f87613f8ad42 {
  meta:
    description = "datamaliciousorder - file 20151208_9dd4633f23abe0230bc4f87613f8ad42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "901578faab53758f7569a4cac55c181e0a2746a325884df7a4d71284f0d5e121"

  strings:
    $s1  = "function dWuZEsa(WpCKxaJnquMPwrVCHRlApHngZdxDbJPIUOMl) {return !isNaN(parseFloat(WpCKxaJnquMPwrVCHRlApHngZdxDbJPIUOMl)) && isFin" ascii
    $s2  = "function dWuZEsa(WpCKxaJnquMPwrVCHRlApHngZdxDbJPIUOMl) {return !isNaN(parseFloat(WpCKxaJnquMPwrVCHRlApHngZdxDbJPIUOMl)) && isFin" ascii
    $s3  = "push(\"46\");f.push(\"88\");f.push(\"77\");f.push(\"76\");f.push(\"72\");f.push(\"34\");f.push(\"59\");f.push(\"13\");f.push(\"1" ascii
    $s4  = "} return JtjPsSihOQn}" fullword ascii
    $s5  = "function KDAwljsZqodywhGsC(adoEg){JtjPsSihOQn= '';for(bRjCPBjEDGR=(-90+90)/451; bRjCPBjEDGR < (992+924)/958; bRjCPBjEDGR++) {BDc" ascii
    $s6  = "function hLLNmwpuTSMCfjSVokWbGORJTSboQrwwsIemuUaraiCHszxmpmmCTZ(rgWnvVirKjVvu,YJjHPyEqqgxTMh){ return LBnZgswdIfkAn[fFlbP(rgWnvV" ascii
    $s7  = "eturn fUvoh;}function FEDBnNHgtznNpeA(eKSbNnzxRcNxXnrgw){eval(eKSbNnzxRcNxXnrgw)}" fullword ascii
    $s8  = "function KDAwljsZqodywhGsC(adoEg){JtjPsSihOQn= '';for(bRjCPBjEDGR=(-90+90)/451; bRjCPBjEDGR < (992+924)/958; bRjCPBjEDGR++) {BDc" ascii
    $s9  = "function hLLNmwpuTSMCfjSVokWbGORJTSboQrwwsIemuUaraiCHszxmpmmCTZ(rgWnvVirKjVvu,YJjHPyEqqgxTMh){ return LBnZgswdIfkAn[fFlbP(rgWnvV" ascii
    $s10 = "push(\"32\");f.push(\"61\");f.push(\"32\");f.push(\"116\");f.push(\"114\");f.push(\"117\");f.push(\"101\");f.push(\"32\");f.push" ascii
    $s11 = "dYGYdJ[bRjCPBjEDGR]=(-542+542)/180; while(true) { if(BDcdYGYdJ[bRjCPBjEDGR] > adoEg[bRjCPBjEDGR].length-(24+188)/212) { break; }" ascii
    $s12 = "push(\"34\");e.push(\"44\");e.push(\"47\");e.push(\"42\");e.push(\"121\");e.push(\"55\");e.push(\"89\");e.push(\"102\");e.push(" ascii
    $s13 = "push(\"109\");f.push(\"47\");f.push(\"119\");f.push(\"112\");f.push(\"45\");f.push(\"105\");f.push(\"110\");f.push(\"99\");f.pus" ascii
    $s14 = "tkm)}function fFlbP(uHUMOWqoQCU,msIGHIOoPBdCd,hzDtCRve){iYZc=parseInt(uHUMOWqoQCU,msIGHIOoPBdCd);fUvoh=iYZc.toString(hzDtCRve);r" ascii
    $s15 = "push(\"10\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"3" ascii
    $s16 = "function ZdWfRLVipAH(jHKiOizF,PupZIj){return jHKiOizF.split(PupZIj)}" fullword ascii
    $s17 = "push(\"51\");e.push(\"53\");e.push(\"48\");e.push(\"45\");e.push(\"49\");e.push(\"53\");e.push(\"48\");e.push(\"41\");e.push(\"3" ascii
    $s18 = "push(\"40\");e.push(\"97\");e.push(\"72\");e.push(\"41\");e.push(\"32\");e.push(\"32\");e.push(\"123\");e.push(\"32\");e.push(\"" ascii
    $s19 = "var LBnZgswdIfkAn=[];for(ezeGtkm=(-373+373)/7;ezeGtkm<(91092+812)/718;ezeGtkm++){LBnZgswdIfkAn[ezeGtkm]=String.fromCharCode(ezeG" ascii
    $s20 = "push(\"59\");e.push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"9\");e.push(\"105\");e.push(\"102\");e.push(\"32\");e.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}