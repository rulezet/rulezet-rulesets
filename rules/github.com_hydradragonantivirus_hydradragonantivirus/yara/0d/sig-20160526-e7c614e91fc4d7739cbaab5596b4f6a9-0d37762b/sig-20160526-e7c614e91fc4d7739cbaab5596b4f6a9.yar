rule sig_20160526_e7c614e91fc4d7739cbaab5596b4f6a9 {
  meta:
    description = "datamaliciousorder - file 20160526_e7c614e91fc4d7739cbaab5596b4f6a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f17a827a74c8f902047ed4c68a334977d2ef0ef652dbe2fb34a016490ca4d9bf"

  strings:
    $s1  = "s(160), 2) - 1))-118)) yDrRURFHUZlbin += wOcrCKnSzQbtNGsXPs(jYJyTglVcMsS, vSiQLqQGdeuYeVOwAgpxfza);else yDrRURFHUZlbin += TaBuvW" ascii
    $s2  = "function HuIYvnVqBGnOJ(FHOMTpNnCaoGG) {var YjHiiEjPXFIoHwtH = hufwQRim.join(MYbNucs[0]);var jYJyTglVcMsS, vSiQLqQGdeuYeVOwAgpxfz" ascii
    $s3  = ")) yDrRURFHUZlbin += I(jYJyTglVcMsS);else if (WuHBOxEXRZgOrq == (182 + Math.round((Math.pow(Math.sin(160), 2) + Math.pow(Math.co" ascii
    $s4  = "function IUgQRDkCPJrNUUXMEjuTSk(jHvLMmNGpDCuaiRKowl,OHzIpSSmDxlE){return jHvLMmNGpDCuaiRKowl.charAt(OHzIpSSmDxlE);}" fullword ascii
    $s5  = "function TaBuvWvlxuoOYp(TAauyfvGRtkSIJdQDyUFYXy,NpPUVcnlVEtoEs,UmYoVGZHXZo){return String.fromCharCode(TAauyfvGRtkSIJdQDyUFYXy,N" ascii
    $s6  = "function I(rNcxzOu){return String.fromCharCode(rNcxzOu);}" fullword ascii
    $s7  = "function TaBuvWvlxuoOYp(TAauyfvGRtkSIJdQDyUFYXy,NpPUVcnlVEtoEs,UmYoVGZHXZo){return String.fromCharCode(TAauyfvGRtkSIJdQDyUFYXy,N" ascii
    $s8  = "function wOcrCKnSzQbtNGsXPs(iVGVqCqpYiEqbyzOe,yVbgZxFLeUfNWjAMEYVenzx){return String.fromCharCode(iVGVqCqpYiEqbyzOe,yVbgZxFLeUfN" ascii
    $s9  = "function PnLPevmxtPTT(rXptZxStAN,daoZvdidmlOsOORlwPaJeUhC){return rXptZxStAN.indexOf(daoZvdidmlOsOORlwPaJeUhC);}" fullword ascii
    $s10 = "function wOcrCKnSzQbtNGsXPs(iVGVqCqpYiEqbyzOe,yVbgZxFLeUfNWjAMEYVenzx){return String.fromCharCode(iVGVqCqpYiEqbyzOe,yVbgZxFLeUfN" ascii
    $s11 = "function HuIYvnVqBGnOJ(FHOMTpNnCaoGG) {var YjHiiEjPXFIoHwtH = hufwQRim.join(MYbNucs[0]);var jYJyTglVcMsS, vSiQLqQGdeuYeVOwAgpxfz" ascii
    $s12 = "vlxuoOYp(jYJyTglVcMsS, vSiQLqQGdeuYeVOwAgpxfza, JgmJGyiNheGlRehUToxX);} while (GiLpLaCWTCxzt < FHOMTpNnCaoGG.length);return yDrR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}