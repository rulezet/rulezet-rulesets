rule sig_20151209_62295cd5f1eabf1d300c9a5b016d9380 {
  meta:
    description = "datamaliciousorder - file 20151209_62295cd5f1eabf1d300c9a5b016d9380.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "852aed37db039b36ccebe3e80fa46d500e3dc7786592f7c2e6b55fc41c4f045c"

  strings:
    $s1  = "function aiwriOv(KUfNAgaUzeUPIIpabCnGWGjQhPvhdSyXxmpd) {return !isNaN(parseFloat(KUfNAgaUzeUPIIpabCnGWGjQhPvhdSyXxmpd)) && isFin" ascii
    $s2  = "function aiwriOv(KUfNAgaUzeUPIIpabCnGWGjQhPvhdSyXxmpd) {return !isNaN(parseFloat(KUfNAgaUzeUPIIpabCnGWGjQhPvhdSyXxmpd)) && isFin" ascii
    $s3  = " wvWnI;}function iRtOGrdbLNxkBXp(YAQJeaCLnlVPJEHpp){eval(YAQJeaCLnlVPJEHpp)}" fullword ascii
    $s4  = "function pgJEkLmjLZgYzIFEF(xpuUC){NemfwTmDAIG= '';for(UQuBqqIBvvy=(-313+313)/569; UQuBqqIBvvy < (1020+606)/813; UQuBqqIBvvy++) {" ascii
    $s5  = "function pgJEkLmjLZgYzIFEF(xpuUC){NemfwTmDAIG= '';for(UQuBqqIBvvy=(-313+313)/569; UQuBqqIBvvy < (1020+606)/813; UQuBqqIBvvy++) {" ascii
    $s6  = "function awmAF(tdsCwjmFGAN,yBAgNSpqailAn,MggvCLVi){yvmF=parseInt(tdsCwjmFGAN,yBAgNSpqailAn);wvWnI=yvmF.toString(MggvCLVi);return" ascii
    $s7  = "function GdrQATOSAln(QresVYhg,xUClwX){return QresVYhg.split(xUClwX)}" fullword ascii
    $s8  = "iUHrNZEGC[UQuBqqIBvvy]=(-620+620)/883; while(true) { if(iUHrNZEGC[UQuBqqIBvvy] > xpuUC[UQuBqqIBvvy].length-(-554+760)/206) { bre" ascii
    $s9  = "function jNeTIBEMuarOzUBCRrPKwZaHZRUyyqaoAUgImvScgrwyqzlfMJkexa(WMuxCNhrnDTpF,fvYUbBhKiVpvTi){ return KexqQ[awmAF(WMuxCNhrnDTpF[" ascii
    $s10 = "function jNeTIBEMuarOzUBCRrPKwZaHZRUyyqaoAUgImvScgrwyqzlfMJkexa(WMuxCNhrnDTpF,fvYUbBhKiVpvTi){ return KexqQ[awmAF(WMuxCNhrnDTpF[" ascii
    $s11 = "]++;}} return NemfwTmDAIG}" fullword ascii
    $s12 = "function awmAF(tdsCwjmFGAN,yBAgNSpqailAn,MggvCLVi){yvmF=parseInt(tdsCwjmFGAN,yBAgNSpqailAn);wvWnI=yvmF.toString(MggvCLVi);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}