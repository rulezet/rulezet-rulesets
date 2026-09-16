rule sig_20151217_9629fef4fd6e51fc0549b012c1ce3952 {
  meta:
    description = "datamaliciousorder - file 20151217_9629fef4fd6e51fc0549b012c1ce3952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e06440ea69a22d9d17a75502a0c9e0483155605688ade52d5b30438e441f6e32"

  strings:
    $s1  = "th.pow(Math.cos(621), 2) - 1)); while(true) { if(uzvSLvkiI[UoArSUyTUjV] > lsqnx[UoArSUyTUjV].length-(-74+821)/747) { break; } if" ascii
    $s2  = "pow(Math.cos(820), 2) - 1)));} uzvSLvkiI[UoArSUyTUjV]++;}UoArSUyTUjV++;} return cjlfreHLWAH}" fullword ascii
    $s3  = ") - 1));while(true){if (UoArSUyTUjV >= (4058+196)/709){break;}uzvSLvkiI[UoArSUyTUjV]=Math.round((Math.pow(Math.sin(621), 2) + Ma" ascii
    $s4  = "function fxkUxfzGrwuEDansA(lsqnx){cjlfreHLWAH= '';UoArSUyTUjV=Math.round((Math.pow(Math.sin(177), 2) + Math.pow(Math.cos(177), 2" ascii
    $s5  = "function fxkUxfzGrwuEDansA(lsqnx){cjlfreHLWAH= '';UoArSUyTUjV=Math.round((Math.pow(Math.sin(177), 2) + Math.pow(Math.cos(177), 2" ascii
    $s6  = "XOZvIUBrZXJEZOLUysioOrFTTERVhMqwDUQ([lsqnx[UoArSUyTUjV][uzvSLvkiI[UoArSUyTUjV]]], Math.round((Math.pow(Math.sin(820), 2) + Math." ascii
    $s7  = "function IYKMCbl(irxHlTDBMGyzmjrOSOdzqonktZdIdDzhdQdx) {return !vUenvpkGYut(UmwGGwZEiXNoTFz(irxHlTDBMGyzmjrOSOdzqonktZdIdDzhdQdx" ascii
    $s8  = "function UmwGGwZEiXNoTFz(gkLzcomMDopmXjcTrXl) {return parseFloat(gkLzcomMDopmXjcTrXl);}" fullword ascii
    $s9  = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s10 = "function IJbuVHuZAvjFjITZHSIXOZvIUBrZXJEZOLUysioOrFTTERVhMqwDUQ(atfUtmxDvGxtT,SBzqXJLRvptzVS){ return pgEHMkm[SlVivIyT[YAnoU(atf" ascii
    $s11 = "function vUenvpkGYut(USoNpzhmOnLLDr) {return isNaN(USoNpzhmOnLLDr);}" fullword ascii
    $s12 = "function W(jqzfXMRCsjoa,mXorbneSiKUfNX){jqzfXMRCsjoa.push(mXorbneSiKUfNX);}" fullword ascii
    $s13 = "function IYKMCbl(irxHlTDBMGyzmjrOSOdzqonktZdIdDzhdQdx) {return !vUenvpkGYut(UmwGGwZEiXNoTFz(irxHlTDBMGyzmjrOSOdzqonktZdIdDzhdQdx" ascii
    $s14 = "function PGeVawGkeCYznLuiy(vsqKdeZtkZ,tBHEtDRAWN) {return parseInt(vsqKdeZtkZ,tBHEtDRAWN);}" fullword ascii
    $s15 = "function IJbuVHuZAvjFjITZHSIXOZvIUBrZXJEZOLUysioOrFTTERVhMqwDUQ(atfUtmxDvGxtT,SBzqXJLRvptzVS){ return pgEHMkm[SlVivIyT[YAnoU(atf" ascii
    $s16 = "function YAnoU(jEkCuZHCQrt,ckiPZaAoIhAne,hNiyhtWF){IAHb=PGeVawGkeCYznLuiy(jEkCuZHCQrt,ckiPZaAoIhAne);UZeNY=IAHb.toString(hNiyhtW" ascii
    $s17 = "function YAnoU(jEkCuZHCQrt,ckiPZaAoIhAne,hNiyhtWF){IAHb=PGeVawGkeCYznLuiy(jEkCuZHCQrt,ckiPZaAoIhAne);UZeNY=IAHb.toString(hNiyhtW" ascii
    $s18 = "function y(WCinoWxHFLVuqw,oKnXKuZsBemqu,mNvQJwKVxfP) {WCinoWxHFLVuqw[oKnXKuZsBemqu]=mNvQJwKVxfP;}" fullword ascii
    $s19 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s20 = "function lHVisUVQfNJlgcr(CbTZnDGVVOOWkwEIX,KvyxIpltURldVzrklySzjizFcuKiHxaLJq,LwoLYGceraufbIEZkzZKYFHQYPwgcbMYODy){eval(CbTZnDGV" ascii

  condition:
    uint16(0) == 0x6c53 and
    8 of them
}