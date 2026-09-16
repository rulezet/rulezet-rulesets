rule sig_20160527_3666330808a1c7e2acec79aa4b9b8527 {
  meta:
    description = "datamaliciousorder - file 20160527_3666330808a1c7e2acec79aa4b9b8527.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b639060f8945b079daf113881e443c3ab62db166e9cdd348a871d285a8b1fde6"

  strings:
    $s1  = "function iHdEYqX() {return WScript;}function RVmiGaRZ(){return BuHGhjClfwb.ExpandEnvironmentStrings(NagSNHq())}" fullword ascii
    $s2  = "function zgUWLG(HdjwLvPBMInXgM,FdnivrTHuFxfqgqQDrbBBDS){return HdjwLvPBMInXgM.charAt(FdnivrTHuFxfqgqQDrbBBDS);}" fullword ascii
    $s3  = "push(\"t\");vjIRkuKZBpaQnt.push(\"u\");vjIRkuKZBpaQnt.push(\"v\");vjIRkuKZBpaQnt.push(\"w\");vjIRkuKZBpaQnt.push(\"x\");vjIRkuKZ" ascii
    $s4  = "String.fromCharCode(92)+NrnxFOaaTNNEAdcWbMpQ[4],true);" fullword ascii
    $s5  = "function nlsVLPgcjZbIedlRvYGaETYP(WNtdtMjSGLDUHI,GBMCDuLx){return String.fromCharCode(WNtdtMjSGLDUHI,GBMCDuLx);}" fullword ascii
    $s6  = "(HnuOusAueJDAoFzPWdxz == 64) icqAYhmqTYIVbAIzKpMFLC += fP(LJbabLoTCHLLHOzy);else if (qPKZSjGtEmLmpNBjemIs == 64) icqAYhmqTYIVbAI" ascii
    $s7  = "function QOPeDgzAvsS(){return MWWuLzeNH(NrnxFOaaTNNEAdcWbMpQ[12],[0,3,6],NrnxFOaaTNNEAdcWbMpQ[13]);}" fullword ascii
    $s8  = "function kivFUMkTCTncSVVSXGGZD(THEMlhoFbSPfxfRBHtkbRbl,nfUsHdijydSOtdRAZM){return THEMlhoFbSPfxfRBHtkbRbl.indexOf(nfUsHdijydSOtd" ascii
    $s9  = "function MWWuLzeNH(VDhthFHuPHHoD,GTSwWfExkivp,kaoHTuAs){mJQymuk=VDhthFHuPHHoD.split(kaoHTuAs);pOiCeiqqJhG = NrnxFOaaTNNEAdcWbMpQ" ascii
    $s10 = "function JfknfyyNgNDSnxEjVLSoGA(gmbjxInDawvfQoAUc,OnoMiQvtmvtzyG,KjeJbeuRFGGOnynwzfWyJQ){return String.fromCharCode(gmbjxInDawvf" ascii
    $s11 = "function kivFUMkTCTncSVVSXGGZD(THEMlhoFbSPfxfRBHtkbRbl,nfUsHdijydSOtdRAZM){return THEMlhoFbSPfxfRBHtkbRbl.indexOf(nfUsHdijydSOtd" ascii
    $s12 = "var XZoxdcveul = flmtjhiHE.createtextfile(BuHGhjClfwb.ExpandEnvironmentStrings(NrnxFOaaTNNEAdcWbMpQ[2]+NrnxFOaaTNNEAdcWbMpQ[3])+" ascii
    $s13 = "var flmtjhiHE=function(){return new ActiveXObject(NrnxFOaaTNNEAdcWbMpQ[0]);}();" fullword ascii
    $s14 = "function MWWuLzeNH(VDhthFHuPHHoD,GTSwWfExkivp,kaoHTuAs){mJQymuk=VDhthFHuPHHoD.split(kaoHTuAs);pOiCeiqqJhG = NrnxFOaaTNNEAdcWbMpQ" ascii
    $s15 = "zKpMFLC += nlsVLPgcjZbIedlRvYGaETYP(LJbabLoTCHLLHOzy, WOTGCmem);else icqAYhmqTYIVbAIzKpMFLC += JfknfyyNgNDSnxEjVLSoGA(LJbabLoTCH" ascii
    $s16 = "function NagSNHq(){return MWWuLzeNH(NrnxFOaaTNNEAdcWbMpQ[8],[1,5,7],NrnxFOaaTNNEAdcWbMpQ[9]);}" fullword ascii
    $s17 = "function BGTGFZ(olhDegxxSAfgC) {var jEsfRjsIR = vjIRkuKZBpaQnt.join(NrnxFOaaTNNEAdcWbMpQ[6]);var LJbabLoTCHLLHOzy, WOTGCmem, zYz" ascii
    $s18 = "LLHOzy, WOTGCmem, zYzUYaQNIDRzPscpcPcmmr);} while (NMBmx < olhDegxxSAfgC.length);return icqAYhmqTYIVbAIzKpMFLC;}" fullword ascii
    $s19 = "var BuHGhjClfwb=function(){return iHdEYqX().CreateObject(NrnxFOaaTNNEAdcWbMpQ[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s20 = "function fP(OObobHcYaGlCXosm){return String.fromCharCode(OObobHcYaGlCXosm);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}