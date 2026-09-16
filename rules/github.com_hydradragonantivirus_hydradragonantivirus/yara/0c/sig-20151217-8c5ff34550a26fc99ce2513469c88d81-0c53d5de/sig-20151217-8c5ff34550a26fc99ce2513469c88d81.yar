rule sig_20151217_8c5ff34550a26fc99ce2513469c88d81 {
  meta:
    description = "datamaliciousorder - file 20151217_8c5ff34550a26fc99ce2513469c88d81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26c237bd3601822596fe43775a28ea4ce1ffa70105494cbbc64840faf0e65721"

  strings:
    $s1  = "th.pow(Math.cos(119), 2) - 1)); while(true) { if(SFFFmwYQT[DmspahWUDQj] > crBbc[DmspahWUDQj].length-(469+123)/592) { break; } if" ascii
    $s2  = "pow(Math.cos(755), 2) - 1)));} SFFFmwYQT[DmspahWUDQj]++;}DmspahWUDQj++;} return cpXPDxVfHlx}" fullword ascii
    $s3  = ") - 1));while(true){if (DmspahWUDQj >= (3952+134)/681){break;}SFFFmwYQT[DmspahWUDQj]=Math.round((Math.pow(Math.sin(119), 2) + Ma" ascii
    $s4  = "function fSebcEtSCpRZENjmc(crBbc){cpXPDxVfHlx= '';DmspahWUDQj=Math.round((Math.pow(Math.sin(701), 2) + Math.pow(Math.cos(701), 2" ascii
    $s5  = "GmtpcIFdYnLrmAFGxvzhXDaOPrmPBeixlNH([crBbc[DmspahWUDQj][SFFFmwYQT[DmspahWUDQj]]], Math.round((Math.pow(Math.sin(755), 2) + Math." ascii
    $s6  = "function fSebcEtSCpRZENjmc(crBbc){cpXPDxVfHlx= '';DmspahWUDQj=Math.round((Math.pow(Math.sin(701), 2) + Math.pow(Math.cos(701), 2" ascii
    $s7  = "function jQinUGf(PEqCGvPjVYkDKiYQHlcMMrVjkYPhEeazglxb) {return !jETtVIMAbHt(jGgFvOkvYLtwCVt(PEqCGvPjVYkDKiYQHlcMMrVjkYPhEeazglxb" ascii
    $s8  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s9  = "function jQinUGf(PEqCGvPjVYkDKiYQHlcMMrVjkYPhEeazglxb) {return !jETtVIMAbHt(jGgFvOkvYLtwCVt(PEqCGvPjVYkDKiYQHlcMMrVjkYPhEeazglxb" ascii
    $s10 = "function sWrdiEKpkEIW(wShzwExkiMGLd) {return isFinite(wShzwExkiMGLd);}" fullword ascii
    $s11 = "function TbTmQ(zNuzVImEOsn,ekvAZHMCjCbDL,VcZqBxlx){kjZa=jEnzcOfHrlEEEBGlk(zNuzVImEOsn,ekvAZHMCjCbDL);AGbol=kjZa.toString(VcZqBxl" ascii
    $s12 = "function ETcKrzKZYeDYnqUgJvKGmtpcIFdYnLrmAFGxvzhXDaOPrmPBeixlNH(aIGCxZiknCPCp,SsaiXcDlfdVyCh){ return jhxriok[tSfdGytX[TbTmQ(aIG" ascii
    $s13 = "function r(vDOAhsjbLdjS,mfNCIyRVkXXUUj){vDOAhsjbLdjS.push(mfNCIyRVkXXUUj);}" fullword ascii
    $s14 = "x);return AGbol;}" fullword ascii
    $s15 = "function ghdtuBuDqkDHKNf(GoloKFFcYwXgPvYeW,BEFaHtxQUHGIZPtcnWUHIdLzIyImPQpLrE,DtZNwZUNxAOdmnNJycoWdxMMmnanvgUbelg){eval(GoloKFFc" ascii
    $s16 = "function TbTmQ(zNuzVImEOsn,ekvAZHMCjCbDL,VcZqBxlx){kjZa=jEnzcOfHrlEEEBGlk(zNuzVImEOsn,ekvAZHMCjCbDL);AGbol=kjZa.toString(VcZqBxl" ascii
    $s17 = "function ghdtuBuDqkDHKNf(GoloKFFcYwXgPvYeW,BEFaHtxQUHGIZPtcnWUHIdLzIyImPQpLrE,DtZNwZUNxAOdmnNJycoWdxMMmnanvgUbelg){eval(GoloKFFc" ascii
    $s18 = "function jGgFvOkvYLtwCVt(mHGBbCmvGPsBRIxQRKz) {return parseFloat(mHGBbCmvGPsBRIxQRKz);}" fullword ascii
    $s19 = "function ETcKrzKZYeDYnqUgJvKGmtpcIFdYnLrmAFGxvzhXDaOPrmPBeixlNH(aIGCxZiknCPCp,SsaiXcDlfdVyCh){ return jhxriok[tSfdGytX[TbTmQ(aIG" ascii
    $s20 = "function jETtVIMAbHt(nXByqkiymhmSGp) {return isNaN(nXByqkiymhmSGp);}" fullword ascii

  condition:
    uint16(0) == 0x5374 and
    8 of them
}