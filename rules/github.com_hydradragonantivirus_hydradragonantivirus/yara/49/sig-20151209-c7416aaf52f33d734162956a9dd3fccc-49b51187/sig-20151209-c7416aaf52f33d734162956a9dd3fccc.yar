rule sig_20151209_c7416aaf52f33d734162956a9dd3fccc {
  meta:
    description = "datamaliciousorder - file 20151209_c7416aaf52f33d734162956a9dd3fccc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ba8197f8526822fbcb339c919c1efd9cb5e75a8644f4dbc1e4853f4d74963db"

  strings:
    $s1  = "function XLsPSDc(VMyettDxqhXfGlcQulNNCHkfceFeZFgpCorF) {return !isNaN(parseFloat(VMyettDxqhXfGlcQulNNCHkfceFeZFgpCorF)) && isFin" ascii
    $s2  = "function XLsPSDc(VMyettDxqhXfGlcQulNNCHkfceFeZFgpCorF) {return !isNaN(parseFloat(VMyettDxqhXfGlcQulNNCHkfceFeZFgpCorF)) && isFin" ascii
    $s3  = "function YYjSDmNfOWPBgjvmw(GRYHb){FxwGogPTKPh= '';for(RfvenLIvkZX=(-257+257)/981; RfvenLIvkZX < (110+734)/422; RfvenLIvkZX++) {u" ascii
    $s4  = "function ciRkOPYJXTB(QerblpnU,UFPONs){return QerblpnU.split(UFPONs)}" fullword ascii
    $s5  = "function XfdSS(EAbmNwtsLwp,gufwbacwimfsf,tPfKZidr){VFIT=parseInt(EAbmNwtsLwp,gufwbacwimfsf);WMXhy=VFIT.toString(tPfKZidr);return" ascii
    $s6  = "function XfdSS(EAbmNwtsLwp,gufwbacwimfsf,tPfKZidr){VFIT=parseInt(EAbmNwtsLwp,gufwbacwimfsf);WMXhy=VFIT.toString(tPfKZidr);return" ascii
    $s7  = " WMXhy;}function wCMEXMEkCEghmOJ(trzurIJUqEFAuXwxq){eval(trzurIJUqEFAuXwxq)}" fullword ascii
    $s8  = "}} return FxwGogPTKPh}" fullword ascii
    $s9  = "JMQfJnuf[RfvenLIvkZX]=(-760+760)/215; while(true) { if(uJMQfJnuf[RfvenLIvkZX] > GRYHb[RfvenLIvkZX].length-(547+87)/634) { break;" ascii
    $s10 = "function ycKsZnwZEuMAyFSAlCAGTkhAuZoxIdpNWUUxWOcrNiHOcDcSbzGsRT(ZcfGKbwoTQeJJ,EQqazJjZYJxGOG){ return bxGUJ[XfdSS(ZcfGKbwoTQeJJ[" ascii
    $s11 = "function YYjSDmNfOWPBgjvmw(GRYHb){FxwGogPTKPh= '';for(RfvenLIvkZX=(-257+257)/981; RfvenLIvkZX < (110+734)/422; RfvenLIvkZX++) {u" ascii
    $s12 = "function ycKsZnwZEuMAyFSAlCAGTkhAuZoxIdpNWUUxWOcrNiHOcDcSbzGsRT(ZcfGKbwoTQeJJ,EQqazJjZYJxGOG){ return bxGUJ[XfdSS(ZcfGKbwoTQeJJ[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}