rule sig_20151217_4a8aeb53552f83e95a19660405833180 {
  meta:
    description = "datamaliciousorder - file 20151217_4a8aeb53552f83e95a19660405833180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9babaf7047079cf5702c6346f4a0421481e9f403a0e8a20589812c138c8b60de"

  strings:
    $s1  = ") - 1));while(true){if (wXiEliCynHG >= (2867+607)/579){break;}xAKUafKDj[wXiEliCynHG]=Math.round((Math.pow(Math.sin(570), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(570), 2) - 1)); while(true) { if(xAKUafKDj[wXiEliCynHG] > mTuvg[wXiEliCynHG].length-(-326+400)/74) { break; } if" ascii
    $s3  = "function bplPAbFSlsaNJfvAo(mTuvg){gXcncDndMsM= '';wXiEliCynHG=Math.round((Math.pow(Math.sin(108), 2) + Math.pow(Math.cos(108), 2" ascii
    $s4  = "w(Math.cos(739), 2) - 1)));} xAKUafKDj[wXiEliCynHG]++;}wXiEliCynHG++;} return gXcncDndMsM}" fullword ascii
    $s5  = "function bplPAbFSlsaNJfvAo(mTuvg){gXcncDndMsM= '';wXiEliCynHG=Math.round((Math.pow(Math.sin(108), 2) + Math.pow(Math.cos(108), 2" ascii
    $s6  = "function PqrLZGZeTIXL(ssRgETmmyASUx) {return isFinite(ssRgETmmyASUx);}" fullword ascii
    $s7  = "function XPepuFY(xRtAjbScpvZJVuiSbyAuuMnRQNpUhjacFxNz) {return !tzJxKTnEHvI(DQwpNRDWNqTyWEj(xRtAjbScpvZJVuiSbyAuuMnRQNpUhjacFxNz" ascii
    $s8  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s9  = "function XPepuFY(xRtAjbScpvZJVuiSbyAuuMnRQNpUhjacFxNz) {return !tzJxKTnEHvI(DQwpNRDWNqTyWEj(xRtAjbScpvZJVuiSbyAuuMnRQNpUhjacFxNz" ascii
    $s10 = "function e(dCnpDoGmADKydG,dhgbrxahMjJAJ,upBMlnDDqWP) {dCnpDoGmADKydG[dhgbrxahMjJAJ]=upBMlnDDqWP;}" fullword ascii
    $s11 = "function hKNIM(SIhMBFuOgvN,LImnmXSCzHZpw,SmXLhnXU){JeyT=heMgbTOFXfLFgghPf(SIhMBFuOgvN,LImnmXSCzHZpw);sVoyg=JeyT.toString(SmXLhnX" ascii
    $s12 = "function tzJxKTnEHvI(SfDIGqKYIPkCJA) {return isNaN(SfDIGqKYIPkCJA);}" fullword ascii
    $s13 = "function hKNIM(SIhMBFuOgvN,LImnmXSCzHZpw,SmXLhnXU){JeyT=heMgbTOFXfLFgghPf(SIhMBFuOgvN,LImnmXSCzHZpw);sVoyg=JeyT.toString(SmXLhnX" ascii
    $s14 = "function doWhxBvRHvhptkr(LkfkLDZoozWeqiVNq,aiChxliOejCzjHkkichBefUlLXrrbYbhIJ,WxlmndlKZGnHECwqAdrSEESTGpGChLOHCOk){eval(LkfkLDZo" ascii
    $s15 = "U);return sVoyg;}" fullword ascii
    $s16 = "function DQwpNRDWNqTyWEj(suRRaCWTvekACRjExkY) {return parseFloat(suRRaCWTvekACRjExkY);}" fullword ascii
    $s17 = "function W(RPnTIskOnIXa,RAWbikErWjXJCU){RPnTIskOnIXa.push(RAWbikErWjXJCU);}" fullword ascii
    $s18 = "function OjgUjDUNULEZAMBgLWtnRHArHdrRNyUwEmnsdymYfLnACjViXhDnrY(kRmkFblXMfIuN,UERwbQpKXcnUMw){ return HFcwjWe[RpHzFcsT[hKNIM(kRm" ascii
    $s19 = "function heMgbTOFXfLFgghPf(qsYqCfNTdP,HAwcEzGdgu) {return parseInt(qsYqCfNTdP,HAwcEzGdgu);}" fullword ascii
    $s20 = "function doWhxBvRHvhptkr(LkfkLDZoozWeqiVNq,aiChxliOejCzjHkkichBefUlLXrrbYbhIJ,WxlmndlKZGnHECwqAdrSEESTGpGChLOHCOk){eval(LkfkLDZo" ascii

  condition:
    uint16(0) == 0x7052 and
    8 of them
}