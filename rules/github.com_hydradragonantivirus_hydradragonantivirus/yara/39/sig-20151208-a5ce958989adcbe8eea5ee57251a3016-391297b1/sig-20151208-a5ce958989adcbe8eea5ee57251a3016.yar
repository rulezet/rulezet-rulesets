rule sig_20151208_a5ce958989adcbe8eea5ee57251a3016 {
  meta:
    description = "datamaliciousorder - file 20151208_a5ce958989adcbe8eea5ee57251a3016.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a734b8bc9b2dcb87448f77212151e5f35219c6bc4adb9ccb580c43d0a4ed83b"

  strings:
    $s1  = "function lTfleJW(tuIRKGGISbQbyfZijUYeCMmtdPyesjFzlXFl) {return !isNaN(parseFloat(tuIRKGGISbQbyfZijUYeCMmtdPyesjFzlXFl)) && isFin" ascii
    $s2  = "function lTfleJW(tuIRKGGISbQbyfZijUYeCMmtdPyesjFzlXFl) {return !isNaN(parseFloat(tuIRKGGISbQbyfZijUYeCMmtdPyesjFzlXFl)) && isFin" ascii
    $s3  = "function TzABAZNnLfEHxLOHMuTTKWoHVRUqTDIcWQghbfUfZgtToWNkVcUauC(QXaYtwycOkBie,PmAAzHZORFixSC){ return fYrjIwxGZHdSj[hMXWJ(QXaYtw" ascii
    $s4  = "jMIHm)}function hMXWJ(BojvmVEQYUt,GyUDZmDeeUrSC,iWLoYoWL){RRnY=parseInt(BojvmVEQYUt,GyUDZmDeeUrSC);JDDCD=RRnY.toString(iWLoYoWL)" ascii
    $s5  = "push(\"57\");t.push(\"48\");t.push(\"57\");t.push(\"50\");t.push(\"57\");t.push(\"53\");t.push(\"57\");t.push(\"54\");t.push(\"1" ascii
    $s6  = "function IzbQdKZlQXGKfHTia(uWGVk){LyeSdouNOxW= '';for(JuzarDZJWdL=(-818+818)/345; JuzarDZJWdL < (57+171)/114; JuzarDZJWdL++) {EJ" ascii
    $s7  = "function IzbQdKZlQXGKfHTia(uWGVk){LyeSdouNOxW= '';for(JuzarDZJWdL=(-818+818)/345; JuzarDZJWdL < (57+171)/114; JuzarDZJWdL++) {EJ" ascii
    $s8  = "push(\"68\");f.push(\"97\");f.push(\"116\");f.push(\"101\");f.push(\"40\");f.push(\"41\");f.push(\"41\");f.push(\"62\");f.push(" ascii
    $s9  = "push(\"77\");t.push(\"80\");t.push(\"37\");t.push(\"92\");t.push(\"92\");t.push(\"34\");t.push(\"59\");t.push(\"13\");t.push(\"1" ascii
    $s10 = "function mrDmYxgEUTL(BNlgdCqI,ixQoRC){return BNlgdCqI.split(ixQoRC)}" fullword ascii
    $s11 = "}} return LyeSdouNOxW}" fullword ascii
    $s12 = "qkCHPRf[JuzarDZJWdL]=(-317+317)/923; while(true) { if(EJqkCHPRf[JuzarDZJWdL] > uWGVk[JuzarDZJWdL].length-(574+184)/758) { break;" ascii
    $s13 = "push(\"32\");f.push(\"99\");f.push(\"97\");f.push(\"116\");f.push(\"99\");f.push(\"104\");f.push(\"32\");f.push(\"40\");f.push(" ascii
    $s14 = "push(\"52\");f.push(\"53\");f.push(\"50\");f.push(\"79\");f.push(\"57\");f.push(\"70\");f.push(\"42\");f.push(\"47\");f.push(\"4" ascii
    $s15 = "push(\"45\");t.push(\"105\");t.push(\"110\");t.push(\"99\");t.push(\"108\");t.push(\"117\");t.push(\"100\");t.push(\"101\");t.pu" ascii
    $s16 = "function TzABAZNnLfEHxLOHMuTTKWoHVRUqTDIcWQghbfUfZgtToWNkVcUauC(QXaYtwycOkBie,PmAAzHZORFixSC){ return fYrjIwxGZHdSj[hMXWJ(QXaYtw" ascii
    $s17 = "push(\"47\");f.push(\"82\");f.push(\"117\");f.push(\"110\");f.push(\"40\");f.push(\"66\");f.push(\"66\");f.push(\"82\");f.push(" ascii
    $s18 = "var fYrjIwxGZHdSj=[];for(djjMIHm=(-586+586)/805;djjMIHm<(77483+597)/610;djjMIHm++){fYrjIwxGZHdSj[djjMIHm]=String.fromCharCode(dj" ascii
    $s19 = ";return JDDCD;}function qxwmERFiAjMTGYD(CatEBFDeYdMzDjhAQ){eval(CatEBFDeYdMzDjhAQ)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}