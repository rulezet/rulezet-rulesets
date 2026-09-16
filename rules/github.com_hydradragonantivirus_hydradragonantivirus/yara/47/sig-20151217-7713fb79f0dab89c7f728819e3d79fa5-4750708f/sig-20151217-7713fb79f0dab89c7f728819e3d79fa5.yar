rule sig_20151217_7713fb79f0dab89c7f728819e3d79fa5 {
  meta:
    description = "datamaliciousorder - file 20151217_7713fb79f0dab89c7f728819e3d79fa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d886969198933f1fb964423966c2c96eec19b872812e3e90fe3569a28c9c968"

  strings:
    $s1  = "th.pow(Math.cos(478), 2) - 1)); while(true) { if(zMoYwcGUN[WllBuIlsSeW] > qXlCq[WllBuIlsSeW].length-(20+943)/963) { break; } if " ascii
    $s2  = "ow(Math.cos(163), 2) - 1)));} zMoYwcGUN[WllBuIlsSeW]++;}WllBuIlsSeW++;} return EzjtnlJMmcq}" fullword ascii
    $s3  = ") - 1));while(true){if (WllBuIlsSeW >= (4144+848)/832){break;}zMoYwcGUN[WllBuIlsSeW]=Math.round((Math.pow(Math.sin(478), 2) + Ma" ascii
    $s4  = "function ELdtsAiyepcaHdOwP(qXlCq){EzjtnlJMmcq= '';WllBuIlsSeW=Math.round((Math.pow(Math.sin(310), 2) + Math.pow(Math.cos(310), 2" ascii
    $s5  = "function ELdtsAiyepcaHdOwP(qXlCq){EzjtnlJMmcq= '';WllBuIlsSeW=Math.round((Math.pow(Math.sin(310), 2) + Math.pow(Math.cos(310), 2" ascii
    $s6  = "function aFDAWDM(WfazQBnRxfUWgIEWNXEIlzgOnADjpYWwoPje) {return !qlqSDrkzoCz(EFJDkomcTuJxjBW(WfazQBnRxfUWgIEWNXEIlzgOnADjpYWwoPje" ascii
    $s7  = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s8  = "function qlqSDrkzoCz(dFibnJjiUdrrwi) {return isNaN(dFibnJjiUdrrwi);}" fullword ascii
    $s9  = "b);return Hcpme;}" fullword ascii
    $s10 = "var q = new Array();q[0]=[];q[0][0]='d';q[0][1]='a';q[0][2]='d';q[0][3]='a';q[0][4]='46';q[0][5]='3d';q[0][6]='42';q[0][7]='14';" ascii
    $s11 = "function JhhNfRoEuDudvjhJu(peJinppzdz,DfEthDFhLt) {return parseInt(peJinppzdz,DfEthDFhLt);}" fullword ascii
    $s12 = "function l(KuhwqUMqHQwd,gVlKUBrxBVXDHI){KuhwqUMqHQwd.push(gVlKUBrxBVXDHI);}" fullword ascii
    $s13 = "function fgdslKbyTgUrMaR(vTACNQndjNrNDmigd,YhOHcEINPmljdYzpxeRQdTdzaVcwSoPbow,RXRVJguKoNjjrcSHINkPvSyOYNcYtjlnGmr){eval(vTACNQnd" ascii
    $s14 = "function aFDAWDM(WfazQBnRxfUWgIEWNXEIlzgOnADjpYWwoPje) {return !qlqSDrkzoCz(EFJDkomcTuJxjBW(WfazQBnRxfUWgIEWNXEIlzgOnADjpYWwoPje" ascii
    $s15 = "function UcIAmZlJiLEJXswEisNfVQUUeBjKcRTjWLloNPcTIURCSjlKkBpqwe(sbEvTxmAxkSfK,aRvbhdpgMJoYOP){ return lNAoPdn[BHYQxqwH[bUJVr(sbE" ascii
    $s16 = "function UcIAmZlJiLEJXswEisNfVQUUeBjKcRTjWLloNPcTIURCSjlKkBpqwe(sbEvTxmAxkSfK,aRvbhdpgMJoYOP){ return lNAoPdn[BHYQxqwH[bUJVr(sbE" ascii
    $s17 = "function bUJVr(CjXAjbZvGjm,lfiQPcmjqPiVQ,gQLdRABb){oEue=JhhNfRoEuDudvjhJu(CjXAjbZvGjm,lfiQPcmjqPiVQ);Hcpme=oEue.toString(gQLdRAB" ascii
    $s18 = "function EFJDkomcTuJxjBW(iUNbBsDSoCUepQdrAfY) {return parseFloat(iUNbBsDSoCUepQdrAfY);}" fullword ascii
    $s19 = "function GhLbDgjoRvXy(jCNyOAqxIxjQH) {return isFinite(jCNyOAqxIxjQH);}" fullword ascii
    $s20 = ",')','T','V','6','W','S',']','A','A','$','X','D','d','2','W','Y','i','z','J',',',']','Z','Z','C','<','e','C','[','/',']',String." ascii

  condition:
    uint16(0) == 0x4842 and
    8 of them
}