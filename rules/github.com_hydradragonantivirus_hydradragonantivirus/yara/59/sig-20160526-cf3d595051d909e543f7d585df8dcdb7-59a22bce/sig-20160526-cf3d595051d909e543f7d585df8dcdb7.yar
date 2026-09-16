rule sig_20160526_cf3d595051d909e543f7d585df8dcdb7 {
  meta:
    description = "datamaliciousorder - file 20160526_cf3d595051d909e543f7d585df8dcdb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0347b5584721fa8b072409856193198890e1d40d671a702cea3342f0ec4485f"

  strings:
    $s1  = "LtfnOQ);else if (KbVZCkgybKLFsiLhcJwtOV == (274 + Math.round((Math.pow(Math.sin(192), 2) + Math.pow(Math.cos(192), 2) - 1))-210)" ascii
    $s2  = "function oQQQgb(dZygWEqbmMyTP) {var KCVCiInNPrCpQK = cdnIusSKgpPBNDJzeo.join(JGuLqGymRgXMZOLmoqk[0]);var RHObrNPLtfnOQ, NCCmMjiL" ascii
    $s3  = "function uZYIxtcNCyzQ(gHZAThLROCrkXbaPrFQAEPrs,UeWKewJurz){return gHZAThLROCrkXbaPrFQAEPrs.charAt(UeWKewJurz);}" fullword ascii
    $s4  = "function uCXsIteUuVzU(xMevFvliueKCmdua,dEzsmONKddNZZjUkWLMgJm){return xMevFvliueKCmdua.indexOf(dEzsmONKddNZZjUkWLMgJm);}" fullword ascii
    $s5  = "function gh(RozpzaLrQiVOawQVkGrUpnA){return String.fromCharCode(RozpzaLrQiVOawQVkGrUpnA);}" fullword ascii
    $s6  = "function xOgoKBpmYKruwapVsx(inRnXrylCokfENTOQTfgVGU,eQHvFRPqnrPJitLwzG,LNYquPxaALC){return String.fromCharCode(inRnXrylCokfENTOQ" ascii
    $s7  = "function qduDufvs(PZnBXHxleDzyICJvNHyh,HtESIDZSwsieevPaTj){return String.fromCharCode(PZnBXHxleDzyICJvNHyh,HtESIDZSwsieevPaTj);}" ascii
    $s8  = "function oQQQgb(dZygWEqbmMyTP) {var KCVCiInNPrCpQK = cdnIusSKgpPBNDJzeo.join(JGuLqGymRgXMZOLmoqk[0]);var RHObrNPLtfnOQ, NCCmMjiL" ascii
    $s9  = "function xOgoKBpmYKruwapVsx(inRnXrylCokfENTOQTfgVGU,eQHvFRPqnrPJitLwzG,LNYquPxaALC){return String.fromCharCode(inRnXrylCokfENTOQ" ascii
    $s10 = ") rBMNqIRxAdDHZLUAG += qduDufvs(RHObrNPLtfnOQ, NCCmMjiL);else rBMNqIRxAdDHZLUAG += xOgoKBpmYKruwapVsx(RHObrNPLtfnOQ, NCCmMjiL, F" ascii
    $s11 = "cogCvaaNKK);} while (gVTmlexwkVUjpZ < dZygWEqbmMyTP.length);return rBMNqIRxAdDHZLUAG;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}