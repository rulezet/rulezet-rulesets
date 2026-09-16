rule sig_20151216_9951a5c6c1f9e73f6453b5a6f23d8118 {
  meta:
    description = "datamaliciousorder - file 20151216_9951a5c6c1f9e73f6453b5a6f23d8118.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71c919d30df7a82b6f0f27af7665dc7f985a9c00342673fef7a6232232817eff"

  strings:
    $s1  = "w(Math.cos(297), 2) - 1)));} DFDthCWwh[RPJPWBdUkXg]++;}RPJPWBdUkXg++;} return yGyAvjFDKNz}" fullword ascii
    $s2  = ") - 1));while(true){if (RPJPWBdUkXg >= (1149+207)/226){break;}DFDthCWwh[RPJPWBdUkXg]=Math.round((Math.pow(Math.sin(628), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(628), 2) - 1)); while(true) { if(DFDthCWwh[RPJPWBdUkXg] > KIPGR[RPJPWBdUkXg].length-(-16+725)/709) { break; } if" ascii
    $s4  = "function LNvbwKxlbooriEnJn(KIPGR){yGyAvjFDKNz= '';RPJPWBdUkXg=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s5  = "function LNvbwKxlbooriEnJn(KIPGR){yGyAvjFDKNz= '';RPJPWBdUkXg=Math.round((Math.pow(Math.sin(358), 2) + Math.pow(Math.cos(358), 2" ascii
    $s6  = "function owDLVXY(QqbvCWGjzDQMyYZeRophMapAXjHCSXVJzJmI) {return !KrofJZBFcwK(DKfIUjmQszGZNrV(QqbvCWGjzDQMyYZeRophMapAXjHCSXVJzJmI" ascii
    $s7  = "function DKfIUjmQszGZNrV(OyDxvODUXcmyfJbFsmt) {return parseFloat(OyDxvODUXcmyfJbFsmt);}" fullword ascii
    $s8  = "function yxyIOFGYbXkT(YoEOiQPjligAg) {return isFinite(YoEOiQPjligAg);}" fullword ascii
    $s9  = "function GRrbcbHtRbVTlnP(AbVvcYQGyKPIsiAUn,BfWKmPoBfNABaxizPyKhMlvEwMBuLenwzL,lPLFgtOrALxXpxRrJrdpymJqufewdkZNsZg){eval(AbVvcYQG" ascii
    $s10 = "function PaPWisxyGgVswnala(LUkGNtXVVi,fXDZyLKOTs) {return parseInt(LUkGNtXVVi,fXDZyLKOTs);}" fullword ascii
    $s11 = "function GRrbcbHtRbVTlnP(AbVvcYQGyKPIsiAUn,BfWKmPoBfNABaxizPyKhMlvEwMBuLenwzL,lPLFgtOrALxXpxRrJrdpymJqufewdkZNsZg){eval(AbVvcYQG" ascii
    $s12 = "function T(eHUXfDRIIQpDib,eMKfUWzAQNyUl,cXYfotwPLeA) {eHUXfDRIIQpDib[eMKfUWzAQNyUl]=cXYfotwPLeA;}" fullword ascii
    $s13 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s14 = "function gVJeU(eTPBzEONdTv,SmzHQAVUMmghB,OfEmTtEg){rgsw=PaPWisxyGgVswnala(eTPBzEONdTv,SmzHQAVUMmghB);vAADk=rgsw.toString(OfEmTtE" ascii
    $s15 = "function KrofJZBFcwK(ueLiFrYNSvStBn) {return isNaN(ueLiFrYNSvStBn);}" fullword ascii
    $s16 = "function owDLVXY(QqbvCWGjzDQMyYZeRophMapAXjHCSXVJzJmI) {return !KrofJZBFcwK(DKfIUjmQszGZNrV(QqbvCWGjzDQMyYZeRophMapAXjHCSXVJzJmI" ascii
    $s17 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s18 = "function gVJeU(eTPBzEONdTv,SmzHQAVUMmghB,OfEmTtEg){rgsw=PaPWisxyGgVswnala(eTPBzEONdTv,SmzHQAVUMmghB);vAADk=rgsw.toString(OfEmTtE" ascii
    $s19 = "function PqiVOsyrApTODNvBiRvVGIJbjlruXnZdjlOXzfvamzFxhWMQvtVpZC(JkgHrFkrIJwrG,jWLDODXEDXeDPR){ return INgpvKl[xlfCWOzF[gVJeU(Jkg" ascii
    $s20 = "g);return vAADk;}" fullword ascii

  condition:
    uint16(0) == 0x6c78 and
    8 of them
}