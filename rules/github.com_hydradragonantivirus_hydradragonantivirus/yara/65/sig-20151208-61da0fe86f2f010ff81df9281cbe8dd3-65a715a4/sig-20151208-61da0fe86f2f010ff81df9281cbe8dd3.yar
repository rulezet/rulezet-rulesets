rule sig_20151208_61da0fe86f2f010ff81df9281cbe8dd3 {
  meta:
    description = "datamaliciousorder - file 20151208_61da0fe86f2f010ff81df9281cbe8dd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1647bd99aa05886219ba1e0a1110272cfb47b06d6c054584918c7476291e61f5"

  strings:
    $s1  = "function WbkHQohAcmd(FAvrNUnP,RAXzmj){return FAvrNUnP.split(RAXzmj)}" fullword ascii
    $s2  = "function lRyxTjQ(zBCLHDDfXbNFebHtjWHPLehXzkdRYYIDnool) {return !isNaN(parseFloat(zBCLHDDfXbNFebHtjWHPLehXzkdRYYIDnool)) && isFin" ascii
    $s3  = "function lRyxTjQ(zBCLHDDfXbNFebHtjWHPLehXzkdRYYIDnool) {return !isNaN(parseFloat(zBCLHDDfXbNFebHtjWHPLehXzkdRYYIDnool)) && isFin" ascii
    $s4  = "push(\"59\");d.push(\"9\");d.push(\"32\");d.push(\"13\");d.push(\"10\");d.push(\"32\");d.push(\"32\");d.push(\"32\");d.push(\"32" ascii
    $s5  = "push(\"87\");V.push(\"83\");V.push(\"99\");V.push(\"114\");V.push(\"105\");V.push(\"34\");V.push(\"58\");V.push(\"34\");V.push(" ascii
    $s6  = "function gecNpMTZoxoTXeKlI(EQVfp){vUBiXtIvBwN= '';for(umsGTmbMKsy=(-371+371)/874; umsGTmbMKsy < (1117+377)/747; umsGTmbMKsy++) {" ascii
    $s7  = "function uJkuqPtyqjYBFEQSHmwYUnOcxTwpWapTPKfddWMLiTDcDKTinVtBcv(kVbUYIDKtmBsy,eFuXRlaIhkaMVH){ return rayyuuzJZpmoI[yBUqC(kVbUYI" ascii
    $s8  = "push(\"32\");V.push(\"34\");V.push(\"84\");V.push(\"84\");V.push(\"80\");V.push(\"34\");V.push(\"59\");V.push(\"13\");V.push(\"1" ascii
    $s9  = "push(\"61\");d.push(\"32\");d.push(\"97\");d.push(\"59\");d.push(\"32\");d.push(\"98\");d.push(\"114\");d.push(\"101\");d.push(" ascii
    $s10 = "push(\"32\");d.push(\"32\");d.push(\"32\");d.push(\"79\");d.push(\"65\");d.push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"4" ascii
    $s11 = "]++;}} return vUBiXtIvBwN}" fullword ascii
    $s12 = "Leuvhlrlk[umsGTmbMKsy]=(-665+665)/195; while(true) { if(Leuvhlrlk[umsGTmbMKsy] > EQVfp[umsGTmbMKsy].length-(-443+834)/391) { bre" ascii
    $s13 = "push(\"61\");d.push(\"32\");d.push(\"49\");d.push(\"59\");d.push(\"32\");d.push(\"98\");d.push(\"79\");d.push(\"74\");d.push(\"4" ascii
    $s14 = "push(\"52\");d.push(\"49\");d.push(\"54\");d.push(\"51\");d.push(\"48\");d.push(\"48\");d.push(\"73\");d.push(\"87\");d.push(\"6" ascii
    $s15 = "function uJkuqPtyqjYBFEQSHmwYUnOcxTwpWapTPKfddWMLiTDcDKTinVtBcv(kVbUYIDKtmBsy,eFuXRlaIhkaMVH){ return rayyuuzJZpmoI[yBUqC(kVbUYI" ascii
    $s16 = ";return mRqnq;}function kEMAmUTBdkqExjM(vDdLGDIerCpDwZNxD){eval(vDdLGDIerCpDwZNxD)}" fullword ascii
    $s17 = "push(\"34\");V.push(\"88\");V.push(\"77\");V.push(\"76\");V.push(\"34\");V.push(\"43\");V.push(\"40\");V.push(\"49\");V.push(\"5" ascii
    $s18 = "push(\"70\");d.push(\"67\");d.push(\"42\");d.push(\"47\");d.push(\"51\");d.push(\"45\");d.push(\"50\");d.push(\"44\");d.push(\"4" ascii
    $s19 = "zUbSh)}function yBUqC(yBFlNSsKmsb,cxELoFbpQvvpH,OaoAjUVm){vHCl=parseInt(yBFlNSsKmsb,cxELoFbpQvvpH);mRqnq=vHCl.toString(OaoAjUVm)" ascii
    $s20 = "push(\"32\");d.push(\"116\");d.push(\"114\");d.push(\"121\");d.push(\"32\");d.push(\"32\");d.push(\"123\");d.push(\"13\");d.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}