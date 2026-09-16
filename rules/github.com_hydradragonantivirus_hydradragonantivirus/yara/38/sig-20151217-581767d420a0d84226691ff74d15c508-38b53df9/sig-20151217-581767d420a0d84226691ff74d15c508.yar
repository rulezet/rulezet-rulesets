rule sig_20151217_581767d420a0d84226691ff74d15c508 {
  meta:
    description = "datamaliciousorder - file 20151217_581767d420a0d84226691ff74d15c508.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e5dc91cc8561c7d1ec17197d36829bcd39c2957c3305a98408404213f01058"

  strings:
    $s1  = "ath.cos(584), 2) - 1)));} sEgbnxQgC[dTeXhZPLxHw]++;}dTeXhZPLxHw++;} return HuVUtUWaglK}" fullword ascii
    $s2  = "function YcGoWkXfxrFatOnXn(tOWEk){HuVUtUWaglK= '';dTeXhZPLxHw=Math.round((Math.pow(Math.sin(449), 2) + Math.pow(Math.cos(449), 2" ascii
    $s3  = ".pow(Math.cos(1), 2) - 1)); while(true) { if(sEgbnxQgC[dTeXhZPLxHw] > tOWEk[dTeXhZPLxHw].length-(-918+982)/64) { break; } if (Sw" ascii
    $s4  = ") - 1));while(true){if (dTeXhZPLxHw >= (2395+263)/443){break;}sEgbnxQgC[dTeXhZPLxHw]=Math.round((Math.pow(Math.sin(1), 2) + Math" ascii
    $s5  = "function YcGoWkXfxrFatOnXn(tOWEk){HuVUtUWaglK= '';dTeXhZPLxHw=Math.round((Math.pow(Math.sin(449), 2) + Math.pow(Math.cos(449), 2" ascii
    $s6  = "function SwpqKch(wiebNmgNPMOOwyGfYhVWtLbRhuHewGBnSZwl) {return !hIWgMbJaMCP(FJCFPdCcQqNnygE(wiebNmgNPMOOwyGfYhVWtLbRhuHewGBnSZwl" ascii
    $s7  = "function YuSCKibTTBedNOKZqeAIjnbbDadDwemlcYMYmFhdKXZkpfrYrhJbhv(sDErUnhfnRRVh,oOAjZqGsPbhOrk){ return gKwQaPI[XLyWuMkB[rQVjh(sDE" ascii
    $s8  = "function YuSCKibTTBedNOKZqeAIjnbbDadDwemlcYMYmFhdKXZkpfrYrhJbhv(sDErUnhfnRRVh,oOAjZqGsPbhOrk){ return gKwQaPI[XLyWuMkB[rQVjh(sDE" ascii
    $s9  = "function SwpqKch(wiebNmgNPMOOwyGfYhVWtLbRhuHewGBnSZwl) {return !hIWgMbJaMCP(FJCFPdCcQqNnygE(wiebNmgNPMOOwyGfYhVWtLbRhuHewGBnSZwl" ascii
    $s10 = ",'J','L','(','Z','W','n','g','!','=','n','(',':','g','X','O','_','v','Y','X','D','S','+','&','Z','Q','B','N','&','[','w',String." ascii
    $s11 = "function cYNvpsarYgzlLjgtu(aKmBnqOPKl,tSJWDmBMJR) {return parseInt(aKmBnqOPKl,tSJWDmBMJR);}" fullword ascii
    $s12 = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s13 = "r);return uyYmr;}" fullword ascii
    $s14 = "function ZliwmrLLCdRZCtL(bjEdVcdFCgPjHBxuh,HWUOJDKGdhCkCDzpQEfOUGropEecjKfRNF,mjGZknYYCBBnUPGAzSJXNtXYVsSFufsGUyW){eval(bjEdVcdF" ascii
    $s15 = "function hIWgMbJaMCP(GpuEpkXYMmsmFR) {return isNaN(GpuEpkXYMmsmFR);}" fullword ascii
    $s16 = "var g = new Array();g[0]=[];g[0][0]='d';g[0][1]='a';g[0][2]='d';g[0][3]='a';g[0][4]='46';g[0][5]='3d';g[0][6]='42';g[0][7]='14';" ascii
    $s17 = "function tIkkUiIGjAVC(OWqMkgxqXgwMf) {return isFinite(OWqMkgxqXgwMf);}" fullword ascii
    $s18 = "function rQVjh(OJTbLtNunOr,nKQqXmHpjIjpE,dHGQCROr){VrLC=cYNvpsarYgzlLjgtu(OJTbLtNunOr,nKQqXmHpjIjpE);uyYmr=VrLC.toString(dHGQCRO" ascii
    $s19 = "function FJCFPdCcQqNnygE(QNLiSvMqRSAnacPIwla) {return parseFloat(QNLiSvMqRSAnacPIwla);}" fullword ascii
    $s20 = "function rQVjh(OJTbLtNunOr,nKQqXmHpjIjpE,dHGQCROr){VrLC=cYNvpsarYgzlLjgtu(OJTbLtNunOr,nKQqXmHpjIjpE);uyYmr=VrLC.toString(dHGQCRO" ascii

  condition:
    uint16(0) == 0x4c58 and
    8 of them
}