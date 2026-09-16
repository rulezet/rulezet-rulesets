rule sig_20151210_b1532097da2d18e847b94ffbfd2dbbd8 {
  meta:
    description = "datamaliciousorder - file 20151210_b1532097da2d18e847b94ffbfd2dbbd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80fc568ee88923cc62fef2c41830be70b2a2d752d79be639b6093fabc5b1ca76"

  strings:
    $s1  = "function EIyOfBX(AfwYuQMrVisAeVfhRIIJRhFNDFTzDxbruzJa) {return !isNaN(parseFloat(AfwYuQMrVisAeVfhRIIJRhFNDFTzDxbruzJa)) && isFin" ascii
    $s2  = "function EIyOfBX(AfwYuQMrVisAeVfhRIIJRhFNDFTzDxbruzJa) {return !isNaN(parseFloat(AfwYuQMrVisAeVfhRIIJRhFNDFTzDxbruzJa)) && isFin" ascii
    $s3  = "function Ohcvy(SuPQQCxcoTd,jpvTJwuFoFgYN,rBGYNdnT){ogiA=parseInt(SuPQQCxcoTd,jpvTJwuFoFgYN);iolcb=ogiA.toString(rBGYNdnT);return" ascii
    $s4  = "EYuhteR=(-658+658)/106;while(true){if(EYuhteR>=(103997+963)/820){break;}BKGTuetxTNLWH[EYuhteR]=String.fromCharCode(EYuhteR);EYuh" ascii
    $s5  = "function UtGVoqHPCFXokddaX(uPIKX){ivmVlGqoSKm= '';for(izWtkAzWkTm=(-251+251)/923; izWtkAzWkTm < (102+996)/549; izWtkAzWkTm++) {q" ascii
    $s6  = "function KcdaIAmYmzF(ttTLiSme,ymfloq){return ttTLiSme.split(ymfloq)}" fullword ascii
    $s7  = "function Ohcvy(SuPQQCxcoTd,jpvTJwuFoFgYN,rBGYNdnT){ogiA=parseInt(SuPQQCxcoTd,jpvTJwuFoFgYN);iolcb=ogiA.toString(rBGYNdnT);return" ascii
    $s8  = "EYuhteR=(-658+658)/106;while(true){if(EYuhteR>=(103997+963)/820){break;}BKGTuetxTNLWH[EYuhteR]=String.fromCharCode(EYuhteR);EYuh" ascii
    $s9  = "+;}} return ivmVlGqoSKm}" fullword ascii
    $s10 = " iolcb;}function foaypbxpFZPSjKZ(CSUsLrgLlOUFgniDd){eval(CSUsLrgLlOUFgniDd)}" fullword ascii
    $s11 = "function UtGVoqHPCFXokddaX(uPIKX){ivmVlGqoSKm= '';for(izWtkAzWkTm=(-251+251)/923; izWtkAzWkTm < (102+996)/549; izWtkAzWkTm++) {q" ascii
    $s12 = "function JWVpRqQwgjPGoqQAtnCPkkdniOzWcpipxpBntkXhkdLAyCHDRvmhyn(aHlOwkjBOoZve,rNPONsuwgokOYk){ return BKGTuetxTNLWH[Ohcvy(aHlOwk" ascii
    $s13 = "BpPPTEUG[izWtkAzWkTm]=(-289+289)/55; while(true) { if(qBpPPTEUG[izWtkAzWkTm] > uPIKX[izWtkAzWkTm].length-(-483+748)/265) { break" ascii
    $s14 = "function JWVpRqQwgjPGoqQAtnCPkkdniOzWcpipxpBntkXhkdLAyCHDRvmhyn(aHlOwkjBOoZve,rNPONsuwgokOYk){ return BKGTuetxTNLWH[Ohcvy(aHlOwk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}