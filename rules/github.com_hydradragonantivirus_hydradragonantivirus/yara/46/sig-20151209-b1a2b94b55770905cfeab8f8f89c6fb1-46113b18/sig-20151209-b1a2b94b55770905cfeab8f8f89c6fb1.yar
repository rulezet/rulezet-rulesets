rule sig_20151209_b1a2b94b55770905cfeab8f8f89c6fb1 {
  meta:
    description = "datamaliciousorder - file 20151209_b1a2b94b55770905cfeab8f8f89c6fb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e277b9aa6ac810985988206d4804c6c0d4d2c917e2ec86ab6d4ac9f32a3ab47"

  strings:
    $s1  = "function JXAbOox(BQQIScOlgaJUGAbkFOnnDlmIoofyrJMwxQjN) {return !isNaN(parseFloat(BQQIScOlgaJUGAbkFOnnDlmIoofyrJMwxQjN)) && isFin" ascii
    $s2  = "function JXAbOox(BQQIScOlgaJUGAbkFOnnDlmIoofyrJMwxQjN) {return !isNaN(parseFloat(BQQIScOlgaJUGAbkFOnnDlmIoofyrJMwxQjN)) && isFin" ascii
    $s3  = "pobztPUUn[jdytfPgwIwc]=(-939+939)/129; while(true) { if(pobztPUUn[jdytfPgwIwc] > gealC[jdytfPgwIwc].length-(688+214)/902) { brea" ascii
    $s4  = "function vhinj(zpciFKTxBwY,cViEBueFbYIoX,qAwmInEW){tfLl=parseInt(zpciFKTxBwY,cViEBueFbYIoX);WNCxB=tfLl.toString(qAwmInEW);return" ascii
    $s5  = "function XzKhoGLJwTqQvFOPCoYhDEuILjvNRKZNDoIrZfealwJnebYqzbXaKS(KhsxkaMRrTwll,dbofDcdIZsGBSI){ return BmRiZ[vhinj(KhsxkaMRrTwll[" ascii
    $s6  = "function vhinj(zpciFKTxBwY,cViEBueFbYIoX,qAwmInEW){tfLl=parseInt(zpciFKTxBwY,cViEBueFbYIoX);WNCxB=tfLl.toString(qAwmInEW);return" ascii
    $s7  = "++;}} return QnHEfZMhvoW}" fullword ascii
    $s8  = "function zEXPFEVxbLMhteMKs(gealC){QnHEfZMhvoW= '';for(jdytfPgwIwc=(-264+264)/424; jdytfPgwIwc < (1361+537)/949; jdytfPgwIwc++) {" ascii
    $s9  = " WNCxB;}function oJyKsmBVknRxsiV(mJxScBVpTfhBFOWGS){eval(mJxScBVpTfhBFOWGS)}" fullword ascii
    $s10 = "function XzKhoGLJwTqQvFOPCoYhDEuILjvNRKZNDoIrZfealwJnebYqzbXaKS(KhsxkaMRrTwll,dbofDcdIZsGBSI){ return BmRiZ[vhinj(KhsxkaMRrTwll[" ascii
    $s11 = "function zEXPFEVxbLMhteMKs(gealC){QnHEfZMhvoW= '';for(jdytfPgwIwc=(-264+264)/424; jdytfPgwIwc < (1361+537)/949; jdytfPgwIwc++) {" ascii
    $s12 = "function qbADHjisXpq(eHkeJmbN,JtQckh){return eHkeJmbN.split(JtQckh)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}