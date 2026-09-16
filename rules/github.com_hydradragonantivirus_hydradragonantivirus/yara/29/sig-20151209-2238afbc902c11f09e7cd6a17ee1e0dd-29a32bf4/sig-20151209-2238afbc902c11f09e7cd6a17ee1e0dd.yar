rule sig_20151209_2238afbc902c11f09e7cd6a17ee1e0dd {
  meta:
    description = "datamaliciousorder - file 20151209_2238afbc902c11f09e7cd6a17ee1e0dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f32b6160b1bc201dcff03f2dd2d1e48596da78d54bd3c39111fc0fc79b6074ce"

  strings:
    $s1  = "function hXurYJh(BGIqKuaLfcwXuBlJeCQzChnOiLuXWFSVeCHP) {return !isNaN(parseFloat(BGIqKuaLfcwXuBlJeCQzChnOiLuXWFSVeCHP)) && isFin" ascii
    $s2  = "function hXurYJh(BGIqKuaLfcwXuBlJeCQzChnOiLuXWFSVeCHP) {return !isNaN(parseFloat(BGIqKuaLfcwXuBlJeCQzChnOiLuXWFSVeCHP)) && isFin" ascii
    $s3  = "push(\"53\");A.push(\"51\");A.push(\"53\");A.push(\"57\");A.push(\"54\");A.push(\"110\");A.push(\"53\");A.push(\"54\");A.push(\"" ascii
    $s4  = "function FtlhQWiBeRWfIeWPQcnsXTwJnYLKhXNkjcjirnoHmtzrHNlCbuVXhZ(KfEaKPeCXwfXP,wQjtibzztehSmH){ return ddaCRdIjyjddY[udBRR(KfEaKP" ascii
    $s5  = "function mTIWMEfIjfNpDEGtI(LfGid){dYXpizozBMq= '';for(edphTPoXKIk=(-51+51)/568; edphTPoXKIk < (1214+62)/638; edphTPoXKIk++) {cJS" ascii
    $s6  = ");return fpzSK;}function qlIiOVAeCbIYMnv(enZFwgUTmbHEJAWHA){eval(enZFwgUTmbHEJAWHA)}" fullword ascii
    $s7  = "push(\"32\");Q.push(\"32\");Q.push(\"110\");Q.push(\"110\");Q.push(\"46\");Q.push(\"47\");Q.push(\"42\");Q.push(\"100\");Q.push(" ascii
    $s8  = "IEnrkB[edphTPoXKIk]=(-737+737)/208; while(true) { if(cJSIEnrkB[edphTPoXKIk] > LfGid[edphTPoXKIk].length-(-336+475)/139) { break;" ascii
    $s9  = "var ddaCRdIjyjddY=[];for(OgznUYx=(-543+543)/917;OgznUYx<(102471+185)/802;OgznUYx++){ddaCRdIjyjddY[OgznUYx]=String.fromCharCode(O" ascii
    $s10 = "push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"1" ascii
    $s11 = "function FtlhQWiBeRWfIeWPQcnsXTwJnYLKhXNkjcjirnoHmtzrHNlCbuVXhZ(KfEaKPeCXwfXP,wQjtibzztehSmH){ return ddaCRdIjyjddY[udBRR(KfEaKP" ascii
    $s12 = ";}} return dYXpizozBMq}" fullword ascii
    $s13 = "push(\"102\");Q.push(\"32\");Q.push(\"40\");Q.push(\"40\");Q.push(\"40\");Q.push(\"110\");Q.push(\"101\");Q.push(\"119\");Q.push" ascii
    $s14 = "function mTIWMEfIjfNpDEGtI(LfGid){dYXpizozBMq= '';for(edphTPoXKIk=(-51+51)/568; edphTPoXKIk < (1214+62)/638; edphTPoXKIk++) {cJS" ascii
    $s15 = "push(\"42\");Q.push(\"111\");Q.push(\"69\");Q.push(\"71\");Q.push(\"68\");Q.push(\"57\");Q.push(\"51\");Q.push(\"72\");Q.push(\"" ascii
    $s16 = "push(\"92\");A.push(\"92\");A.push(\"34\");A.push(\"59\");A.push(\"13\");A.push(\"10\");A.push(\"118\");A.push(\"97\");A.push(\"" ascii
    $s17 = "push(\"32\");Q.push(\"61\");Q.push(\"32\");Q.push(\"48\");Q.push(\"59\");Q.push(\"13\");Q.push(\"10\");Q.push(\"32\");Q.push(\"3" ascii
    $s18 = "push(\"120\");Q.push(\"101\");Q.push(\"34\");Q.push(\"44\");Q.push(\"52\");Q.push(\"45\");Q.push(\"50\");Q.push(\"41\");Q.push(" ascii
    $s19 = "push(\"116\");Q.push(\"46\");Q.push(\"111\");Q.push(\"112\");Q.push(\"101\");Q.push(\"110\");Q.push(\"40\");Q.push(\"112\");Q.pu" ascii
    $s20 = "push(\"40\");A.push(\"50\");A.push(\"48\");A.push(\"52\");A.push(\"49\");A.push(\"51\");A.push(\"48\");A.push(\"44\");A.push(\"3" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}