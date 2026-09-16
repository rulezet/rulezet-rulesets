rule sig_20160526_44a0c49db0a554156c10e3c0d2411d07 {
  meta:
    description = "datamaliciousorder - file 20160526_44a0c49db0a554156c10e3c0d2411d07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e00375e46dfd338175d7b4de42b8cbdfd8df2b0cec341b9939887becc13e7fb"

  strings:
    $s1  = "ziHzEiPVouSTADZD);else if (LHRPUTKAXHrJSjhQv == (818 + Math.round((Math.pow(Math.sin(886), 2) + Math.pow(Math.cos(886), 2) - 1))" ascii
    $s2  = "function MbhFgOvdOFHrd(izMFhvEKgjaiJ) {var pXJKokojNvRmtT = sYGfep.join(DWsMveTBaqdem[0]);var yOBaziHzEiPVouSTADZD, MgHiTNplKplW" ascii
    $s3  = "function rAlGeF(MCmmucarrjwsRZBcotME,VKoVXsKWdEUzPzMNvFEBb){return MCmmucarrjwsRZBcotME.charAt(VKoVXsKWdEUzPzMNvFEBb);}" fullword ascii
    $s4  = "-754)) hfXEIRUrIR += BMMHxSRVracT(yOBaziHzEiPVouSTADZD, MgHiTNplKplWkGlGmZr);else hfXEIRUrIR += LOMoKvhShc(yOBaziHzEiPVouSTADZD," ascii
    $s5  = "function xwmzPgzIeeCNWmGuvCSb(nKNrTJcjDliXunTFCeklUKWu,xZGsqezUomhGSjUpeI){return nKNrTJcjDliXunTFCeklUKWu.indexOf(xZGsqezUomhGS" ascii
    $s6  = "function xwmzPgzIeeCNWmGuvCSb(nKNrTJcjDliXunTFCeklUKWu,xZGsqezUomhGSjUpeI){return nKNrTJcjDliXunTFCeklUKWu.indexOf(xZGsqezUomhGS" ascii
    $s7  = "function BMMHxSRVracT(klhxPLkaPHyBzsJbcjuLSvK,ZHNztADGa){return String.fromCharCode(klhxPLkaPHyBzsJbcjuLSvK,ZHNztADGa);}" fullword ascii
    $s8  = " MgHiTNplKplWkGlGmZr, FlZhFVzT);} while (sUbZMiBZs < izMFhvEKgjaiJ.length);return hfXEIRUrIR;}" fullword ascii
    $s9  = "function LOMoKvhShc(ADXhiJnlZzwQiCH,Ykicxo,ZJAZFJVgyRHVGchzIq){return String.fromCharCode(ADXhiJnlZzwQiCH,Ykicxo,ZJAZFJVgyRHVGch" ascii
    $s10 = "function Qb(RwTVbSlFNtHxVDLsRdji){return String.fromCharCode(RwTVbSlFNtHxVDLsRdji);}" fullword ascii
    $s11 = "function LOMoKvhShc(ADXhiJnlZzwQiCH,Ykicxo,ZJAZFJVgyRHVGchzIq){return String.fromCharCode(ADXhiJnlZzwQiCH,Ykicxo,ZJAZFJVgyRHVGch" ascii
    $s12 = "function MbhFgOvdOFHrd(izMFhvEKgjaiJ) {var pXJKokojNvRmtT = sYGfep.join(DWsMveTBaqdem[0]);var yOBaziHzEiPVouSTADZD, MgHiTNplKplW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}