rule sig_20151210_ad95d5ad799838ec88def994a35ee88c {
  meta:
    description = "datamaliciousorder - file 20151210_ad95d5ad799838ec88def994a35ee88c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "131db2955c481433314be42e9d1f501d4f56789168b83178e8c29cc255b86b51"

  strings:
    $s1  = "function smLzy(DqwzKuFVQgJ,XrqsQvNQIjdaM,AijeyEBC){lVye=parseInt(DqwzKuFVQgJ,XrqsQvNQIjdaM);KlMgF=lVye.toString(AijeyEBC);return" ascii
    $s2  = "function smLzy(DqwzKuFVQgJ,XrqsQvNQIjdaM,AijeyEBC){lVye=parseInt(DqwzKuFVQgJ,XrqsQvNQIjdaM);KlMgF=lVye.toString(AijeyEBC);return" ascii
    $s3  = "function UiVunTh(PtvBnEmKNPBNgRwmqsqBATurwEUFSGqfuXaD) {return !isNaN(parseFloat(PtvBnEmKNPBNgRwmqsqBATurwEUFSGqfuXaD)) && isFin" ascii
    $s4  = "function UiVunTh(PtvBnEmKNPBNgRwmqsqBATurwEUFSGqfuXaD) {return !isNaN(parseFloat(PtvBnEmKNPBNgRwmqsqBATurwEUFSGqfuXaD)) && isFin" ascii
    $s5  = "function VUVlgtzEtBaSEvxRPUDFiivYzzxOgaVocKaxbDTYeNtaATarfyWKCm(BxkAPaALeGpwe,krTKjvroQHXsmL){ return IVotD[smLzy(BxkAPaALeGpwe[" ascii
    $s6  = "function VUVlgtzEtBaSEvxRPUDFiivYzzxOgaVocKaxbDTYeNtaATarfyWKCm(BxkAPaALeGpwe,krTKjvroQHXsmL){ return IVotD[smLzy(BxkAPaALeGpwe[" ascii
    $s7  = "function EaRTrAtVQgD(zeEuHxOK,gGoexn){return zeEuHxOK.split(gGoexn)}" fullword ascii
    $s8  = "function bNIIBjEVrLvhPFaJl(Arvru){ZCdBcoFQCvv= '';for(dzwGrEsLWwh=(-740+740)/684; dzwGrEsLWwh < (1157+127)/642; dzwGrEsLWwh++) {" ascii
    $s9  = "function bNIIBjEVrLvhPFaJl(Arvru){ZCdBcoFQCvv= '';for(dzwGrEsLWwh=(-740+740)/684; dzwGrEsLWwh < (1157+127)/642; dzwGrEsLWwh++) {" ascii
    $s10 = "TikQpQFID[dzwGrEsLWwh]=(-930+930)/98; while(true) { if(TikQpQFID[dzwGrEsLWwh] > Arvru[dzwGrEsLWwh].length-(404+521)/925) { break" ascii
    $s11 = " KlMgF;}function UdUCVaCdsOJGmzb(hdZKomWQMyVwoijAo){eval(hdZKomWQMyVwoijAo)}" fullword ascii
    $s12 = "+;}} return ZCdBcoFQCvv}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}