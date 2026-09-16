rule sig_20151208_8a9dab26a0ba7f4f0d62db3ea03b26d6 {
  meta:
    description = "datamaliciousorder - file 20151208_8a9dab26a0ba7f4f0d62db3ea03b26d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e272d5cfcf2cee1e671d31c10b6d178f7e35c8b062e95f81e5219223ad066b57"

  strings:
    $s1  = "function MKRIZXK(FmgJQAVWijUxvyCqFUVNQDUvVgKeeWAqRSUw) {return !isNaN(parseFloat(FmgJQAVWijUxvyCqFUVNQDUvVgKeeWAqRSUw)) && isFin" ascii
    $s2  = "function MKRIZXK(FmgJQAVWijUxvyCqFUVNQDUvVgKeeWAqRSUw) {return !isNaN(parseFloat(FmgJQAVWijUxvyCqFUVNQDUvVgKeeWAqRSUw)) && isFin" ascii
    $s3  = "push(\"45\");i.push(\"105\");i.push(\"110\");i.push(\"99\");i.push(\"108\");i.push(\"117\");i.push(\"100\");i.push(\"101\");i.pu" ascii
    $s4  = "push(\"59\");V.push(\"32\");V.push(\"13\");V.push(\"10\");V.push(\"32\");V.push(\"32\");V.push(\"32\");V.push(\"32\");V.push(\"1" ascii
    $s5  = "push(\"99\");V.push(\"61\");V.push(\"120\");V.push(\"82\");V.push(\"73\");V.push(\"59\");V.push(\"32\");V.push(\"99\");V.push(\"" ascii
    $s6  = "return vmoMY;}function yDlBOJzQlBqaRya(dyyBMthebZcQMaQFZ){eval(dyyBMthebZcQMaQFZ)}" fullword ascii
    $s7  = "push(\"43\");V.push(\"32\");V.push(\"34\");V.push(\"66\");V.push(\"46\");V.push(\"83\");V.push(\"116\");V.push(\"34\");V.push(\"" ascii
    $s8  = "push(\"106\");V.push(\"46\");V.push(\"115\");V.push(\"105\");V.push(\"122\");V.push(\"101\");V.push(\"32\");V.push(\"62\");V.pus" ascii
    $s9  = "push(\"108\");V.push(\"115\");V.push(\"101\");V.push(\"41\");V.push(\"59\");V.push(\"32\");V.push(\"116\");V.push(\"100\");V.pus" ascii
    $s10 = "push(\"83\");i.push(\"116\");i.push(\"114\");i.push(\"105\");i.push(\"110\");i.push(\"103\");i.push(\"115\");i.push(\"40\");i.pu" ascii
    $s11 = "push(\"45\");V.push(\"56\");V.push(\"49\");V.push(\"55\");V.push(\"41\");V.push(\"32\");V.push(\"32\");V.push(\"123\");V.push(\"" ascii
    $s12 = "push(\"10\");V.push(\"9\");V.push(\"9\");V.push(\"125\");V.push(\"13\");V.push(\"10\");V.push(\"32\");V.push(\"32\");V.push(\"32" ascii
    $s13 = "push(\"32\");i.push(\"120\");i.push(\"79\");i.push(\"32\");i.push(\"61\");i.push(\"32\");i.push(\"87\");i.push(\"83\");i.push(\"" ascii
    $s14 = "MJCx)}function stDdv(QHcUGoYHiQQ,DJmAcUXQfQDTl,QeNfpSZD){XJAK=parseInt(QHcUGoYHiQQ,DJmAcUXQfQDTl);vmoMY=XJAK.toString(QeNfpSZD);" ascii
    $s15 = "function auJQwlGdlwr(gDJyfmTC,iiuSMF){return gDJyfmTC.split(iiuSMF)}" fullword ascii
    $s16 = "push(\"55\");i.push(\"53\");i.push(\"55\");i.push(\"51\");i.push(\"53\");i.push(\"57\");i.push(\"54\");i.push(\"110\");i.push(\"" ascii
    $s17 = "urzfmtIm[AqCPgaVzaEr]=(-765+765)/959; while(true) { if(CurzfmtIm[AqCPgaVzaEr] > PwINB[AqCPgaVzaEr].length-(579+108)/687) { break" ascii
    $s18 = "var poDvqiSiNJvMC=[];for(WKsMJCx=(-444+444)/28;WKsMJCx<(52776+856)/419;WKsMJCx++){poDvqiSiNJvMC[WKsMJCx]=String.fromCharCode(WKs" ascii
    $s19 = "function dnmPeDaeTwkSgJnop(PwINB){nDmotfcAeUL= '';for(AqCPgaVzaEr=(-323+323)/329; AqCPgaVzaEr < (1018+92)/555; AqCPgaVzaEr++) {C" ascii
    $s20 = "function dIWtjtesKwsNAaEYNEgHWFFneGCOZIYLdWxfITAPLJkwBUYcQKPcQu(vxznGJokkXgQa,TtYmPFCrlwoVcm){ return poDvqiSiNJvMC[stDdv(vxznGJ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}