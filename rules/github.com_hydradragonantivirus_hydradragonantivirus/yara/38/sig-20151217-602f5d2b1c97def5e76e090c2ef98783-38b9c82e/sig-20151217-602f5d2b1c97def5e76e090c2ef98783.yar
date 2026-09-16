rule sig_20151217_602f5d2b1c97def5e76e090c2ef98783 {
  meta:
    description = "datamaliciousorder - file 20151217_602f5d2b1c97def5e76e090c2ef98783.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c08c75807bef3b2fc43453655eb6a466ec400aa337bc3571ea507eff8ff4ebc6"

  strings:
    $s1  = "function QdeJhQIanNxbpwwxp(VOafq){pmCCnpzvVFn= '';uzCYnxrIdUP=Math.round((Math.pow(Math.sin(380), 2) + Math.pow(Math.cos(380), 2" ascii
    $s2  = "h.pow(Math.cos(453), 2) - 1)); while(true) { if(EmavFSckL[uzCYnxrIdUP] > VOafq[uzCYnxrIdUP].length-(312+303)/615) { break; } if " ascii
    $s3  = "w(Math.cos(255), 2) - 1)));} EmavFSckL[uzCYnxrIdUP]++;}uzCYnxrIdUP++;} return pmCCnpzvVFn}" fullword ascii
    $s4  = ") - 1));while(true){if (uzCYnxrIdUP >= (665+229)/149){break;}EmavFSckL[uzCYnxrIdUP]=Math.round((Math.pow(Math.sin(453), 2) + Mat" ascii
    $s5  = "function QdeJhQIanNxbpwwxp(VOafq){pmCCnpzvVFn= '';uzCYnxrIdUP=Math.round((Math.pow(Math.sin(380), 2) + Math.pow(Math.cos(380), 2" ascii
    $s6  = "function YtjrCYC(YKJNePzRblbDuPgdsiMrBVGIhdYtFbebvMYi) {return !DbTKoKBlVyx(RwpDDHIOnRzUiLW(YKJNePzRblbDuPgdsiMrBVGIhdYtFbebvMYi" ascii
    $s7  = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s8  = "function E(TqMLNzEiZdeJ,xYysPIHKCeAiXZ){TqMLNzEiZdeJ.push(xYysPIHKCeAiXZ);}" fullword ascii
    $s9  = "function DbTKoKBlVyx(JnCzkNAppBZFpG) {return isNaN(JnCzkNAppBZFpG);}" fullword ascii
    $s10 = "function RwpDDHIOnRzUiLW(BFIQJZdxGNMfgkggrfh) {return parseFloat(BFIQJZdxGNMfgkggrfh);}" fullword ascii
    $s11 = "function HEHxirJrhrQmnJP(qmszrrHxOvQXyefJw,acRqvLgQyBtFkUmxxVCghUoFkXPdNuhPzE,bnIkrHtipIrssboNfvELtcdTwHaMXTGnwyC){eval(qmszrrHx" ascii
    $s12 = "function HEHxirJrhrQmnJP(qmszrrHxOvQXyefJw,acRqvLgQyBtFkUmxxVCghUoFkXPdNuhPzE,bnIkrHtipIrssboNfvELtcdTwHaMXTGnwyC){eval(qmszrrHx" ascii
    $s13 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s14 = "function y(VFjqLlsihxwasy,SYMJOlWBzRBKY,PmNNIMIwwuR) {VFjqLlsihxwasy[SYMJOlWBzRBKY]=PmNNIMIwwuR;}" fullword ascii
    $s15 = "S);return uvbHg;}" fullword ascii
    $s16 = "function YtjrCYC(YKJNePzRblbDuPgdsiMrBVGIhdYtFbebvMYi) {return !DbTKoKBlVyx(RwpDDHIOnRzUiLW(YKJNePzRblbDuPgdsiMrBVGIhdYtFbebvMYi" ascii
    $s17 = "function vfLrnvzdYbfPQXcIUGRQWMJtbEAhDVeiBeYqseuWVGRrYshwGdVWsh(nxeKfAugsUxFR,gXemMInCYoFxfq){ return BblnYsQ[FjBIubcp[UbkGR(nxe" ascii
    $s18 = "function vfLrnvzdYbfPQXcIUGRQWMJtbEAhDVeiBeYqseuWVGRrYshwGdVWsh(nxeKfAugsUxFR,gXemMInCYoFxfq){ return BblnYsQ[FjBIubcp[UbkGR(nxe" ascii
    $s19 = "function GZALSQDUUJIU(yntLUnYxdzDKd) {return isFinite(yntLUnYxdzDKd);}" fullword ascii
    $s20 = "function sQAeHDwglaGzLuMca(LsdNAzEIkM,xgUSlaUDwP) {return parseInt(LsdNAzEIkM,xgUSlaUDwP);}" fullword ascii

  condition:
    uint16(0) == 0x6a46 and
    8 of them
}