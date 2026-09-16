rule sig_20151216_d408ab39eb9d23cdcae8011b8ce73ec5 {
  meta:
    description = "datamaliciousorder - file 20151216_d408ab39eb9d23cdcae8011b8ce73ec5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f65b3b2c9120c409300096d9693292bf2f7227fe7ceb02fa004d17194b89e65"

  strings:
    $s1  = "th.pow(Math.cos(648), 2) - 1)); while(true) { if(tEkUkVnyI[hFIxcmcMgAm] > SBYdc[hFIxcmcMgAm].length-(607+346)/953) { break; } if" ascii
    $s2  = "ow(Math.cos(177), 2) - 1)));} tEkUkVnyI[hFIxcmcMgAm]++;}hFIxcmcMgAm++;} return tDceajpfHYa}" fullword ascii
    $s3  = ") - 1));while(true){if (hFIxcmcMgAm >= (4516+710)/871){break;}tEkUkVnyI[hFIxcmcMgAm]=Math.round((Math.pow(Math.sin(648), 2) + Ma" ascii
    $s4  = "function wiKDKHgXRYBIldGvZ(SBYdc){tDceajpfHYa= '';hFIxcmcMgAm=Math.round((Math.pow(Math.sin(148), 2) + Math.pow(Math.cos(148), 2" ascii
    $s5  = "function wiKDKHgXRYBIldGvZ(SBYdc){tDceajpfHYa= '';hFIxcmcMgAm=Math.round((Math.pow(Math.sin(148), 2) + Math.pow(Math.cos(148), 2" ascii
    $s6  = "function qHpzS(RNCyVeMplov,lceKMKZWYWMLw,JZcsDJNT){vSdD=UBhtZdUICVDZbKiTe(RNCyVeMplov,lceKMKZWYWMLw);MuzcX=vSdD.toString(JZcsDJN" ascii
    $s7  = "T);return MuzcX;}" fullword ascii
    $s8  = "function OLDGtLxpVHawECU(MrTpQjOJcYXtljwAn,UTLyxAlhAgEoPJEkgaLubpkjbnuoIvUZBI,WNyFGNaqAkoToPvPSWHtbDOdtLsPaHgQARA){eval(MrTpQjOJ" ascii
    $s9  = "function UKLrytHkRAxRgXV(uDVxtILYkqcWTZgfnmX) {return parseFloat(uDVxtILYkqcWTZgfnmX);}" fullword ascii
    $s10 = "function w(lhJhAstOhMck,bJBrzTXHQIkKAs){lhJhAstOhMck.push(bJBrzTXHQIkKAs);}" fullword ascii
    $s11 = "function UBhtZdUICVDZbKiTe(pnHYZJFoRm,kbEThOsVWw) {return parseInt(pnHYZJFoRm,kbEThOsVWw);}" fullword ascii
    $s12 = "function qHpzS(RNCyVeMplov,lceKMKZWYWMLw,JZcsDJNT){vSdD=UBhtZdUICVDZbKiTe(RNCyVeMplov,lceKMKZWYWMLw);MuzcX=vSdD.toString(JZcsDJN" ascii
    $s13 = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s14 = "function t(yUoTYYiKIkfswz,LBnGIiHsVJrqz,cYnOEQDtvTR) {yUoTYYiKIkfswz[LBnGIiHsVJrqz]=cYnOEQDtvTR;}" fullword ascii
    $s15 = "function eIOaDQtdGJY(spOMKXiiAVGSdF) {return isNaN(spOMKXiiAVGSdF);}" fullword ascii
    $s16 = "function OLDGtLxpVHawECU(MrTpQjOJcYXtljwAn,UTLyxAlhAgEoPJEkgaLubpkjbnuoIvUZBI,WNyFGNaqAkoToPvPSWHtbDOdtLsPaHgQARA){eval(MrTpQjOJ" ascii
    $s17 = "function kAQAyGEatDTY(OdVyeyxxMWLOq) {return isFinite(OdVyeyxxMWLOq);}" fullword ascii
    $s18 = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s19 = "function ImnHghc(iPtJLCAIgSMznEcyZNFLIxqFBEBkpPkMYhVB) {return !eIOaDQtdGJY(UKLrytHkRAxRgXV(iPtJLCAIgSMznEcyZNFLIxqFBEBkpPkMYhVB" ascii
    $s20 = "function aqgGRTCGybNlVCAsECvtFmEvcsxZRLfREilvaMHJtgXJJFLuwpAtep(lkOeTzdmAYiCE,oNwDLEUGNNSPra){ return lZTYaTR[vJHeoxlP[qHpzS(lkO" ascii

  condition:
    uint16(0) == 0x4a76 and
    8 of them
}