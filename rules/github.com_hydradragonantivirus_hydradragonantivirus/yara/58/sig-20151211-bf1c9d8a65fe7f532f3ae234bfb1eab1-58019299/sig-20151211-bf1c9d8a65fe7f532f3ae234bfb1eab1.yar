rule sig_20151211_bf1c9d8a65fe7f532f3ae234bfb1eab1 {
  meta:
    description = "datamaliciousorder - file 20151211_bf1c9d8a65fe7f532f3ae234bfb1eab1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f047ed7b0bbec9c07503343eb3dea6eb2188a79fad0e7f6df96dd41dab80ebd7"

  strings:
    $s1  = "var c=new Array(\"2f\",\"2b\",\"2f\",\"27\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s2  = "function estiHwNMHtMdkedVOHDtbkRJbyEWLvJVxrgauliXSAZRwoeZeZjSdP(sMkFRfSHTtJZZ,MjDjInQFvBFHmS){ return ucPwG[BadyP(sMkFRfSHTtJZZ[" ascii
    $s3  = " IIiwl;}function qVjyqpfArZufhQH(RswYjetvHiFGgxHPV){eval(RswYjetvHiFGgxHPV)}" fullword ascii
    $s4  = ";}UAqPgdsyGQg++;} return jvNsawANQpR}" fullword ascii
    $s5  = "XRcZpjYm[UAqPgdsyGQg]=(-598+598)/818; while(true) { if(TXRcZpjYm[UAqPgdsyGQg] > nyYdj[UAqPgdsyGQg].length-(144+544)/688) { break" ascii
    $s6  = "var D=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5b\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "function estiHwNMHtMdkedVOHDtbkRJbyEWLvJVxrgauliXSAZRwoeZeZjSdP(sMkFRfSHTtJZZ,MjDjInQFvBFHmS){ return ucPwG[BadyP(sMkFRfSHTtJZZ[" ascii
    $s8  = "var c=new Array(\"2f\",\"2b\",\"2f\",\"27\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s9  = "function BadyP(pRWcPlRmmsZ,AYEucpKNAJuxQ,ysXSouwM){EITE=parseInt(pRWcPlRmmsZ,AYEucpKNAJuxQ);IIiwl=EITE.toString(ysXSouwM);return" ascii
    $s10 = "var D=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"5b\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function BadyP(pRWcPlRmmsZ,AYEucpKNAJuxQ,ysXSouwM){EITE=parseInt(pRWcPlRmmsZ,AYEucpKNAJuxQ);IIiwl=EITE.toString(ysXSouwM);return" ascii
    $s12 = "function HlisogCIleM(mJTaAeFW,khSAbD){return mJTaAeFW.split(khSAbD)}" fullword ascii
    $s13 = "function xFyjdGYURcWdCirVl(nyYdj){jvNsawANQpR= '';UAqPgdsyGQg=(-477+477)/860; while(true){if(UAqPgdsyGQg >= (986+24)/505)break;T" ascii
    $s14 = "function GjkcMca(XzgSymjsryGFeOSpXCRgYouICMugbPXJbFrU) {return !isNaN(parseFloat(XzgSymjsryGFeOSpXCRgYouICMugbPXJbFrU)) && isFin" ascii
    $s15 = "function GjkcMca(XzgSymjsryGFeOSpXCRgYouICMugbPXJbFrU) {return !isNaN(parseFloat(XzgSymjsryGFeOSpXCRgYouICMugbPXJbFrU)) && isFin" ascii
    $s16 = "function xFyjdGYURcWdCirVl(nyYdj){jvNsawANQpR= '';UAqPgdsyGQg=(-477+477)/860; while(true){if(UAqPgdsyGQg >= (986+24)/505)break;T" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}