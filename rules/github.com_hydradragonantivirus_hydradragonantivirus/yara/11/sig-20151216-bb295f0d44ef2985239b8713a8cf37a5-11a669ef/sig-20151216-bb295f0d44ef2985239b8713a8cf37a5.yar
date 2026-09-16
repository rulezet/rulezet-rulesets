rule sig_20151216_bb295f0d44ef2985239b8713a8cf37a5 {
  meta:
    description = "datamaliciousorder - file 20151216_bb295f0d44ef2985239b8713a8cf37a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ace9d3fec7e5ad2cc000386a7c0a93f47891caf848bafc5da3f3620e1c4c830"

  strings:
    $s1  = "function ZJdBteYiABLySFfkW(iEJjB){vuKKRpAhBjv= '';xoxDITEuBpD=Math.round((Math.pow(Math.sin(858), 2) + Math.pow(Math.cos(858), 2" ascii
    $s2  = ") - 1));while(true){if (xoxDITEuBpD >= (4689+201)/815){break;}FlrxkCoFU[xoxDITEuBpD]=Math.round((Math.pow(Math.sin(697), 2) + Ma" ascii
    $s3  = "ow(Math.cos(194), 2) - 1)));} FlrxkCoFU[xoxDITEuBpD]++;}xoxDITEuBpD++;} return vuKKRpAhBjv}" fullword ascii
    $s4  = "th.pow(Math.cos(697), 2) - 1)); while(true) { if(FlrxkCoFU[xoxDITEuBpD] > iEJjB[xoxDITEuBpD].length-(458+437)/895) { break; } if" ascii
    $s5  = "function ZJdBteYiABLySFfkW(iEJjB){vuKKRpAhBjv= '';xoxDITEuBpD=Math.round((Math.pow(Math.sin(858), 2) + Math.pow(Math.cos(858), 2" ascii
    $s6  = "function vpKlvbQ(SICckUnEFwyMclbetPvddnSwvneuFgUgQzjQ) {return !ipvmPnxTElQ(RuZYDhKQKKIaKKk(SICckUnEFwyMclbetPvddnSwvneuFgUgQzjQ" ascii
    $s7  = "function ipvmPnxTElQ(aDnoVskXGbjVOu) {return isNaN(aDnoVskXGbjVOu);}" fullword ascii
    $s8  = "function zvwItxPSUgsibIm(sKwZGgjdpWygTngdR,BITEoWObFfFNOZHmSLBchwFEATUhDvKnIN,WyTeOAcnygtYoNmlfldRdJaaDiUCLHuFdnl){eval(sKwZGgjd" ascii
    $s9  = "function LTacFyasAXCmiWEBMWnreeMgHDqlyPhfaGxPYmttqzyCiamkYQPEBY(XuXAkrkpzppWF,FkmbJIfQfOXwLm){ return SUWYmVT[YzajpJYi[mgUEv(XuX" ascii
    $s10 = "function mgUEv(kjoOVgVrpDp,XoOsWhSmsWCMf,vlADkLNN){palB=JaDYhsJwxiuhzhOAu(kjoOVgVrpDp,XoOsWhSmsWCMf);eYfPD=palB.toString(vlADkLN" ascii
    $s11 = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s12 = "function JaDYhsJwxiuhzhOAu(UjqfTIGcvQ,yrcztOTLFZ) {return parseInt(UjqfTIGcvQ,yrcztOTLFZ);}" fullword ascii
    $s13 = "N);return eYfPD;}" fullword ascii
    $s14 = "function LTacFyasAXCmiWEBMWnreeMgHDqlyPhfaGxPYmttqzyCiamkYQPEBY(XuXAkrkpzppWF,FkmbJIfQfOXwLm){ return SUWYmVT[YzajpJYi[mgUEv(XuX" ascii
    $s15 = "function vpKlvbQ(SICckUnEFwyMclbetPvddnSwvneuFgUgQzjQ) {return !ipvmPnxTElQ(RuZYDhKQKKIaKKk(SICckUnEFwyMclbetPvddnSwvneuFgUgQzjQ" ascii
    $s16 = "var V = new Array();V[0]=[];V[0][0]='d';V[0][1]='a';V[0][2]='d';V[0][3]='a';V[0][4]='46';V[0][5]='3d';V[0][6]='42';V[0][7]='14';" ascii
    $s17 = "function mgUEv(kjoOVgVrpDp,XoOsWhSmsWCMf,vlADkLNN){palB=JaDYhsJwxiuhzhOAu(kjoOVgVrpDp,XoOsWhSmsWCMf);eYfPD=palB.toString(vlADkLN" ascii
    $s18 = "function zvwItxPSUgsibIm(sKwZGgjdpWygTngdR,BITEoWObFfFNOZHmSLBchwFEATUhDvKnIN,WyTeOAcnygtYoNmlfldRdJaaDiUCLHuFdnl){eval(sKwZGgjd" ascii
    $s19 = "function A(NDGvotHxifrM,NBAAPEoFYqSOEH){NDGvotHxifrM.push(NBAAPEoFYqSOEH);}" fullword ascii
    $s20 = "function RMYBuwEenIxx(CvhJuSwvGCKEo) {return isFinite(CvhJuSwvGCKEo);}" fullword ascii

  condition:
    uint16(0) == 0x7a59 and
    8 of them
}