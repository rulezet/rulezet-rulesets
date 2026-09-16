rule sig_20151216_160cf55649f0be6531376028b451918e {
  meta:
    description = "datamaliciousorder - file 20151216_160cf55649f0be6531376028b451918e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11716036f09e142d202583014a244b49eb78ac4ae520e0206fcc30e538f6033e"

  strings:
    $s1  = ") - 1));while(true){if (bfCxRBrBFLr >= (5330+148)/913){break;}FAuuTsyUy[bfCxRBrBFLr]=Math.round((Math.pow(Math.sin(545), 2) + Ma" ascii
    $s2  = "function WIQJWdyUTDbWRbdoK(ycvDk){yoFthIoDszK= '';bfCxRBrBFLr=Math.round((Math.pow(Math.sin(420), 2) + Math.pow(Math.cos(420), 2" ascii
    $s3  = "w(Math.cos(669), 2) - 1)));} FAuuTsyUy[bfCxRBrBFLr]++;}bfCxRBrBFLr++;} return yoFthIoDszK}" fullword ascii
    $s4  = "th.pow(Math.cos(545), 2) - 1)); while(true) { if(FAuuTsyUy[bfCxRBrBFLr] > ycvDk[bfCxRBrBFLr].length-(20+736)/756) { break; } if " ascii
    $s5  = "function WIQJWdyUTDbWRbdoK(ycvDk){yoFthIoDszK= '';bfCxRBrBFLr=Math.round((Math.pow(Math.sin(420), 2) + Math.pow(Math.cos(420), 2" ascii
    $s6  = "function VZIFrkq(uhBIWNdWCdVlhfnimKxKLPWBTwogHVIXNMbD) {return !uLEZfnOhEXl(cDaPpxnjoTvPcEt(uhBIWNdWCdVlhfnimKxKLPWBTwogHVIXNMbD" ascii
    $s7  = "function FBTcHetXyYSHQKt(FEvsnbIGRpwVinVyu,erDiHNhmqiCMADngDdrSbTwTvsZeizltud,LHIZfzsCIsGhCbqAZbypmuYWNgSQhGxBHmX){eval(FEvsnbIG" ascii
    $s8  = "function KcwklpjGZabI(fyYEJXGGKhuPQ) {return isFinite(fyYEJXGGKhuPQ);}" fullword ascii
    $s9  = "function FBTcHetXyYSHQKt(FEvsnbIGRpwVinVyu,erDiHNhmqiCMADngDdrSbTwTvsZeizltud,LHIZfzsCIsGhCbqAZbypmuYWNgSQhGxBHmX){eval(FEvsnbIG" ascii
    $s10 = "function xuWBa(UTkpxcPThjQ,siVWpQFSmFzCR,PQyTCchk){hlHZ=FFHlVzyaiPjzLwIcZ(UTkpxcPThjQ,siVWpQFSmFzCR);OvRRd=hlHZ.toString(PQyTCch" ascii
    $s11 = "function cDaPpxnjoTvPcEt(MuxGJHwnOQEmuKsYmzk) {return parseFloat(MuxGJHwnOQEmuKsYmzk);}" fullword ascii
    $s12 = "function uLEZfnOhEXl(viaMkQTyFjPFcw) {return isNaN(viaMkQTyFjPFcw);}" fullword ascii
    $s13 = "function xuWBa(UTkpxcPThjQ,siVWpQFSmFzCR,PQyTCchk){hlHZ=FFHlVzyaiPjzLwIcZ(UTkpxcPThjQ,siVWpQFSmFzCR);OvRRd=hlHZ.toString(PQyTCch" ascii
    $s14 = "function gydssNgWlLqEZBHjWsKeTuMHVUeksRVdcosKAVhHoMuHFaWMKObyAm(ywaMTpPcsmUKr,rDlVPWQrWMcjEp){ return SyvhmZY[bMQKfjUr[xuWBa(ywa" ascii
    $s15 = "function FFHlVzyaiPjzLwIcZ(jCCQLCjIzu,DVDAlzlqAR) {return parseInt(jCCQLCjIzu,DVDAlzlqAR);}" fullword ascii
    $s16 = "k);return OvRRd;}" fullword ascii
    $s17 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s18 = "function Y(mkgFJjtteFURxg,KjaItzvPptAVX,ZahzxPheTPS) {mkgFJjtteFURxg[KjaItzvPptAVX]=ZahzxPheTPS;}" fullword ascii
    $s19 = "function Q(zITJKsjqRazI,TZKNtDwbPkZYlV){zITJKsjqRazI.push(TZKNtDwbPkZYlV);}" fullword ascii
    $s20 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4d62 and
    8 of them
}