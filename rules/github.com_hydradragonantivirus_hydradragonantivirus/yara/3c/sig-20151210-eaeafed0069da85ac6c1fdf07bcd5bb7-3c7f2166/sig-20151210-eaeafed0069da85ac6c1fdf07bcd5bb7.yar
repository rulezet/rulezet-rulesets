rule sig_20151210_eaeafed0069da85ac6c1fdf07bcd5bb7 {
  meta:
    description = "datamaliciousorder - file 20151210_eaeafed0069da85ac6c1fdf07bcd5bb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525df90134f40edf390fc62b61af408429bda63e65c422e846a78fedbf950df1"

  strings:
    $s1  = "function FEqgWVP(CzCjXhRBDLZJzJgGOJGiSNqejwdkvEkltEXp) {return !isNaN(parseFloat(CzCjXhRBDLZJzJgGOJGiSNqejwdkvEkltEXp)) && isFin" ascii
    $s2  = "function FEqgWVP(CzCjXhRBDLZJzJgGOJGiSNqejwdkvEkltEXp) {return !isNaN(parseFloat(CzCjXhRBDLZJzJgGOJGiSNqejwdkvEkltEXp)) && isFin" ascii
    $s3  = "TYpoQChn[fRDGorzbPaE]=(-690+690)/748; while(true) { if(ZTYpoQChn[fRDGorzbPaE] > pFoBN[fRDGorzbPaE].length-(-579+612)/33) { break" ascii
    $s4  = ";}} return TjMspspQhID}" fullword ascii
    $s5  = "function yRmAOKXpDygWpmopF(pFoBN){TjMspspQhID= '';for(fRDGorzbPaE=(-728+728)/812; fRDGorzbPaE < (692+396)/544; fRDGorzbPaE++) {Z" ascii
    $s6  = "function DcdiD(GaISEHbWTob,AwqZzUYOQnAhL,UWBzxwLA){ZTPL=parseInt(GaISEHbWTob,AwqZzUYOQnAhL);GcikD=ZTPL.toString(UWBzxwLA);return" ascii
    $s7  = "function chHAACWJKPs(nGTrysCE,qqBONu){return nGTrysCE.split(qqBONu)}" fullword ascii
    $s8  = " GcikD;}function yhNFchDavnUaSSj(lbLrzxEfrswuzztGq){eval(lbLrzxEfrswuzztGq)}" fullword ascii
    $s9  = "function gTOtnVFpUklDdbnQXUykaNQMvtVUGRkBFkuTIOrvMxMdYifPEMeswG(VQkJvnoAcQyVn,WrAXlMRcZWLEkK){ return MfaNbSAQLYEJO[DcdiD(VQkJvn" ascii
    $s10 = "zoKmXJO=(-989+989)/991;while(true){if(zoKmXJO>=(85310+322)/669){break;}MfaNbSAQLYEJO[zoKmXJO]=String.fromCharCode(zoKmXJO);zoKmX" ascii
    $s11 = "function yRmAOKXpDygWpmopF(pFoBN){TjMspspQhID= '';for(fRDGorzbPaE=(-728+728)/812; fRDGorzbPaE < (692+396)/544; fRDGorzbPaE++) {Z" ascii
    $s12 = "function DcdiD(GaISEHbWTob,AwqZzUYOQnAhL,UWBzxwLA){ZTPL=parseInt(GaISEHbWTob,AwqZzUYOQnAhL);GcikD=ZTPL.toString(UWBzxwLA);return" ascii
    $s13 = "zoKmXJO=(-989+989)/991;while(true){if(zoKmXJO>=(85310+322)/669){break;}MfaNbSAQLYEJO[zoKmXJO]=String.fromCharCode(zoKmXJO);zoKmX" ascii
    $s14 = "function gTOtnVFpUklDdbnQXUykaNQMvtVUGRkBFkuTIOrvMxMdYifPEMeswG(VQkJvnoAcQyVn,WrAXlMRcZWLEkK){ return MfaNbSAQLYEJO[DcdiD(VQkJvn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}