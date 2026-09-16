rule sig_20160303_5551a3ab7a5e401027f537cefb30d548 {
  meta:
    description = "datamaliciousorder - file 20160303_5551a3ab7a5e401027f537cefb30d548.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "816d5198ebbf62bf8c871c39e84141f95c0c0f364cfaae92fe46491d4b1e58fd"

  strings:
    $s1  = "var hKmRh = \"cfAvtS FAF pt.Shell wJkVvfH Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var BQ = true  , IxoH = WPW[7] + \"\" + WPW[9];" fullword ascii
    $s3  = "return jLtWlxJ[0] + jLtWlxJ[2] + jLtWlxJ[4] + \".F\" + jLtWlxJ[7] + jLtWlxJ[9] + jLtWlxJ[12] + jLtWlxJ[14];" fullword ascii
    $s4  = "var WPW = (wAu + \"TTP\" + \" jeqprJE mfRZo XML ream St mVKdzSVX AD XNKDdvc OD\").split(\" \");" fullword ascii
    $s5  = "var jLtWlxJ = \"Sc JUKJKMG r znUDbdFYH ipting DGNAVVr luX ile DxywiIVaiRGZrp System qL YPvpL Obj DWRtQu ect tShmSxC\".split(\" " ascii
    $s6  = "Dqesz.open(xDMVs,OWKhy,false);" fullword ascii
    $s7  = "function kmFUoAAAb(AzxVx,AAhGP,uPqbO) {" fullword ascii
    $s8  = "function ThWM(pFCov) {" fullword ascii
    $s9  = "function drWB(kmUuf,axkFj) {" fullword ascii
    $s10 = "return Ah.ExpandEnvironmentStrings(hKmRh[6]);" fullword ascii
    $s11 = "function yvNj(LGbQY) {" fullword ascii
    $s12 = "if (((new Date())>0,7345065888)) {" fullword ascii
    $s13 = "function eUFN(Dqesz,OWKhy,xDMVs) {" fullword ascii
    $s14 = "function vSCz(MMcmR) {" fullword ascii
    $s15 = "function iZKV(SIzrm) {" fullword ascii
    $s16 = "function QCep(IEnUE) {" fullword ascii
    $s17 = "function BtvUuxJjt(AeQtCPhlOXY) {" fullword ascii
    $s18 = "return MpCz.responseBody;" fullword ascii
    $s19 = "function ReGsOeE(eqUE) {" fullword ascii
    $s20 = "if (IEnUE > 171474-195){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}