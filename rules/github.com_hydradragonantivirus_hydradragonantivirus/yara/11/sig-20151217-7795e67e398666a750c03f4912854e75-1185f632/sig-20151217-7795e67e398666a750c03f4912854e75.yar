rule sig_20151217_7795e67e398666a750c03f4912854e75 {
  meta:
    description = "datamaliciousorder - file 20151217_7795e67e398666a750c03f4912854e75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de20d692709f53474ad21dd17b848d835312d599604ac2ea2ff32f568709c35"

  strings:
    $s1  = "pow(Math.cos(91), 2) - 1)); while(true) { if(vonkSDJbd[VkCbPwXuAXp] > uBHRa[VkCbPwXuAXp].length-(-162+687)/525) { break; } if (K" ascii
    $s2  = "th.cos(618), 2) - 1)));} vonkSDJbd[VkCbPwXuAXp]++;}VkCbPwXuAXp++;} return uPVxIDfqpWd}" fullword ascii
    $s3  = "function qapQdvkTrOOEOXKVR(uBHRa){uPVxIDfqpWd= '';VkCbPwXuAXp=Math.round((Math.pow(Math.sin(994), 2) + Math.pow(Math.cos(994), 2" ascii
    $s4  = ") - 1));while(true){if (VkCbPwXuAXp >= (554+88)/107){break;}vonkSDJbd[VkCbPwXuAXp]=Math.round((Math.pow(Math.sin(91), 2) + Math." ascii
    $s5  = "function qapQdvkTrOOEOXKVR(uBHRa){uPVxIDfqpWd= '';VkCbPwXuAXp=Math.round((Math.pow(Math.sin(994), 2) + Math.pow(Math.cos(994), 2" ascii
    $s6  = "function KiqmGIm(jWtvkeFvUvIBRNvKjBXTpHfDenxPMvEqPvnG) {return !SXBBurtetCQ(vUGuuoaBuTpqURD(jWtvkeFvUvIBRNvKjBXTpHfDenxPMvEqPvnG" ascii
    $s7  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s8  = "function w(SMrNvBYxSEuU,elORVfgxRUKrPn){SMrNvBYxSEuU.push(elORVfgxRUKrPn);}" fullword ascii
    $s9  = "function ubGOJceqgFoTDtX(pIUoWmpWFOPTKgGYs,WloiODAGWOiPGZOTVEqqlYxXFoeEgnautb,OEzfPMLlVXlZPYcHUJTROwSiKwPhCRkpEgh){eval(pIUoWmpW" ascii
    $s10 = "function ubGOJceqgFoTDtX(pIUoWmpWFOPTKgGYs,WloiODAGWOiPGZOTVEqqlYxXFoeEgnautb,OEzfPMLlVXlZPYcHUJTROwSiKwPhCRkpEgh){eval(pIUoWmpW" ascii
    $s11 = "function IwYEzsgKNpJh(XgEzXuUaemPSX) {return isFinite(XgEzXuUaemPSX);}" fullword ascii
    $s12 = "function bSfQHffMvvjhzTgimoAOFeZQhNSZgGtqGRTtyoVutZhJwtpWpmAvWT(iNkOmSEIpNqOk,xFhaDjewytJfJE){ return BRhRUPs[cIwlONbX[dKKUQ(iNk" ascii
    $s13 = "function bSfQHffMvvjhzTgimoAOFeZQhNSZgGtqGRTtyoVutZhJwtpWpmAvWT(iNkOmSEIpNqOk,xFhaDjewytJfJE){ return BRhRUPs[cIwlONbX[dKKUQ(iNk" ascii
    $s14 = "function SXBBurtetCQ(wxuxGUWDZUmuun) {return isNaN(wxuxGUWDZUmuun);}" fullword ascii
    $s15 = "function bWHKwpRpFLqZyiYSC(eIRLGWiZTh,FeytNKFjlX) {return parseInt(eIRLGWiZTh,FeytNKFjlX);}" fullword ascii
    $s16 = "function KiqmGIm(jWtvkeFvUvIBRNvKjBXTpHfDenxPMvEqPvnG) {return !SXBBurtetCQ(vUGuuoaBuTpqURD(jWtvkeFvUvIBRNvKjBXTpHfDenxPMvEqPvnG" ascii
    $s17 = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s18 = "function R(rrVlstayywlNQU,QYxWNCWkVfMPd,YbXFGXPUlHr) {rrVlstayywlNQU[QYxWNCWkVfMPd]=YbXFGXPUlHr;}" fullword ascii
    $s19 = "function dKKUQ(MgWuxLzlUmC,mqbYWqpeoQXUX,SgyRJgeB){uLRt=bWHKwpRpFLqZyiYSC(MgWuxLzlUmC,mqbYWqpeoQXUX);lwBDs=uLRt.toString(SgyRJge" ascii
    $s20 = "B);return lwBDs;}" fullword ascii

  condition:
    uint16(0) == 0x4963 and
    8 of them
}