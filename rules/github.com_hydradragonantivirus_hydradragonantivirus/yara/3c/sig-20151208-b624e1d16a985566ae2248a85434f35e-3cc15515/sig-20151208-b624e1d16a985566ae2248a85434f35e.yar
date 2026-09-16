rule sig_20151208_b624e1d16a985566ae2248a85434f35e {
  meta:
    description = "datamaliciousorder - file 20151208_b624e1d16a985566ae2248a85434f35e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c3936b2c0b8cd5edcf5a39cb7b18cf6bf09a1e7ae225e101587cda6818985e0"

  strings:
    $s1  = "function rSGLnkl(TdkMoSyjpeMvSPlWmUAjDpHqbeFzPeMDyceB) {return !isNaN(parseFloat(TdkMoSyjpeMvSPlWmUAjDpHqbeFzPeMDyceB)) && isFin" ascii
    $s2  = "function rSGLnkl(TdkMoSyjpeMvSPlWmUAjDpHqbeFzPeMDyceB) {return !isNaN(parseFloat(TdkMoSyjpeMvSPlWmUAjDpHqbeFzPeMDyceB)) && isFin" ascii
    $s3  = "function eDeRgpiXbKXmJHAuV(QGFQz){JDNUGtNWuDI= '';for(XskaAoXKDRn=(-800+800)/705; XskaAoXKDRn < (1112+788)/950; XskaAoXKDRn++) {" ascii
    $s4  = "zzCOdlIms[XskaAoXKDRn]=(-273+273)/394; while(true) { if(zzCOdlIms[XskaAoXKDRn] > QGFQz[XskaAoXKDRn].length-(-114+511)/397) { bre" ascii
    $s5  = "gplMHy)}function BWNMT(IHrzTBUkPqR,LnqtTteWedgot,BqdPZHfM){gNTl=parseInt(IHrzTBUkPqR,LnqtTteWedgot);IBWkb=gNTl.toString(BqdPZHfM" ascii
    $s6  = "function zCYLGLHSosmAVzAQQReRNkiusaUzgLGXyPNilUydBUVMmGAYtdicJV(kdqKfTVQLvQFP,wYLLRKvuGYhitD){ return xugkqHSQdrWuQ[BWNMT(kdqKfT" ascii
    $s7  = "var xugkqHSQdrWuQ=[];for(MgplMHy=(-800+800)/656;MgplMHy<(118666+374)/930;MgplMHy++){xugkqHSQdrWuQ[MgplMHy]=String.fromCharCode(M" ascii
    $s8  = ";}} return JDNUGtNWuDI}" fullword ascii
    $s9  = "push(\"85\");Y.push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"34\");Y.push(\"65\");Y.push(\"68\");Y.push(\"79\");Y.push(\"6" ascii
    $s10 = "push(\"73\");s.push(\"111\");s.push(\"99\");s.push(\"47\");s.push(\"42\");s.push(\"80\");s.push(\"72\");s.push(\"74\");s.push(\"" ascii
    $s11 = "push(\"120\");s.push(\"101\");s.push(\"34\");s.push(\"44\");s.push(\"52\");s.push(\"45\");s.push(\"50\");s.push(\"41\");s.push(" ascii
    $s12 = "function eDeRgpiXbKXmJHAuV(QGFQz){JDNUGtNWuDI= '';for(XskaAoXKDRn=(-800+800)/705; XskaAoXKDRn < (1112+788)/950; XskaAoXKDRn++) {" ascii
    $s13 = "push(\"102\");s.push(\"32\");s.push(\"40\");s.push(\"40\");s.push(\"40\");s.push(\"110\");s.push(\"101\");s.push(\"119\");s.push" ascii
    $s14 = "function zCYLGLHSosmAVzAQQReRNkiusaUzgLGXyPNilUydBUVMmGAYtdicJV(kdqKfTVQLvQFP,wYLLRKvuGYhitD){ return xugkqHSQdrWuQ[BWNMT(kdqKfT" ascii
    $s15 = "function ofFMQPXLxlT(eelTXVdF,pNuWZz){return eelTXVdF.split(pNuWZz)}" fullword ascii
    $s16 = "push(\"61\");s.push(\"32\");s.push(\"49\");s.push(\"41\");s.push(\"32\");s.push(\"32\");s.push(\"123\");s.push(\"13\");s.push(\"" ascii
    $s17 = "push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"34\");Y.push(\"37\");Y.push(\"84\");Y.push(\"69\");Y.push(\"77\");Y.push(\"8" ascii
    $s18 = ");return IBWkb;}function TUNaspUDnvxppNF(meKzRhTYhqnuXlxHh){eval(meKzRhTYhqnuXlxHh)}" fullword ascii
    $s19 = "push(\"32\");s.push(\"32\");s.push(\"88\");s.push(\"71\");s.push(\"46\");s.push(\"47\");s.push(\"42\");s.push(\"100\");s.push(\"" ascii
    $s20 = "push(\"87\");Y.push(\"83\");Y.push(\"99\");Y.push(\"114\");Y.push(\"105\");Y.push(\"34\");Y.push(\"58\");Y.push(\"34\");Y.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}