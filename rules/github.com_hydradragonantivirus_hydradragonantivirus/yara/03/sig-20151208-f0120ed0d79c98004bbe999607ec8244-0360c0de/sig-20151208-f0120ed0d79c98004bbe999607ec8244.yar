rule sig_20151208_f0120ed0d79c98004bbe999607ec8244 {
  meta:
    description = "datamaliciousorder - file 20151208_f0120ed0d79c98004bbe999607ec8244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d378b47570afcab28876af729bc1fb5b42a329c1db7f5f568eeac4b156bc0246"

  strings:
    $s1  = "Rtggng[ysAANBeZRNz]=(-765+765)/836; while(true) { if(EjjRtggng[ysAANBeZRNz] > DpOSt[ysAANBeZRNz].length-(-18+684)/666) { break; " ascii
    $s2  = "function ejYuDWZrUaghtVrFv(DpOSt){omkQXaWLGAK= '';for(ysAANBeZRNz=(-98+98)/207; ysAANBeZRNz < (872+590)/731; ysAANBeZRNz++) {Ejj" ascii
    $s3  = "function ejYuDWZrUaghtVrFv(DpOSt){omkQXaWLGAK= '';for(ysAANBeZRNz=(-98+98)/207; ysAANBeZRNz < (872+590)/731; ysAANBeZRNz++) {Ejj" ascii
    $s4  = "function ZOMAhJL(jsAGwvveVGDVzeLUFhhyzpPtyCneQCYoBSIZ) {return !isNaN(parseFloat(jsAGwvveVGDVzeLUFhhyzpPtyCneQCYoBSIZ)) && isFin" ascii
    $s5  = "push(\"101\");J.push(\"115\");J.push(\"112\");J.push(\"111\");J.push(\"110\");J.push(\"115\");J.push(\"101\");J.push(\"66\");J.p" ascii
    $s6  = "function ZOMAhJL(jsAGwvveVGDVzeLUFhhyzpPtyCneQCYoBSIZ) {return !isNaN(parseFloat(jsAGwvveVGDVzeLUFhhyzpPtyCneQCYoBSIZ)) && isFin" ascii
    $s7  = "push(\"32\");J.push(\"32\");J.push(\"123\");J.push(\"13\");J.push(\"10\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"" ascii
    $s8  = "push(\"116\");Q.push(\"46\");Q.push(\"67\");Q.push(\"114\");Q.push(\"101\");Q.push(\"97\");Q.push(\"116\");Q.push(\"101\");Q.pus" ascii
    $s9  = "push(\"97\");J.push(\"116\");J.push(\"117\");J.push(\"115\");J.push(\"32\");J.push(\"61\");J.push(\"61\");J.push(\"32\");J.push(" ascii
    $s10 = "push(\"86\");J.push(\"46\");J.push(\"115\");J.push(\"101\");J.push(\"110\");J.push(\"100\");J.push(\"40\");J.push(\"41\");J.push" ascii
    $s11 = "push(\"44\");J.push(\"55\");J.push(\"54\");J.push(\"52\");J.push(\"52\");J.push(\"55\");J.push(\"57\");J.push(\"53\");J.push(\"5" ascii
    $s12 = "function KUIqblTtPNgJnFjexEUJyqVjQDRskfRYIBQirBKbaEKTkUctjQXQeR(fpskRLIiTtNlE,KGsfhvQnknNEuy){ return cEIGaHTmMiTvU[VNPHa(fpskRL" ascii
    $s13 = "push(\"42\");J.push(\"47\");J.push(\"34\");J.push(\"46\");J.push(\"101\");J.push(\"120\");J.push(\"101\");J.push(\"34\");J.push(" ascii
    $s14 = "function GUGLfcknJmp(xrFcggvY,PCuLOu){return xrFcggvY.split(PCuLOu)}" fullword ascii
    $s15 = "push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"3" ascii
    $s16 = "push(\"61\");J.push(\"32\");J.push(\"49\");J.push(\"59\");J.push(\"32\");J.push(\"103\");J.push(\"66\");J.push(\"108\");J.push(" ascii
    $s17 = ";return uPYCk;}function gJgYANVqJvVdZQs(ObRYbtSrfKLlyLrxr){eval(ObRYbtSrfKLlyLrxr)}" fullword ascii
    $s18 = "push(\"32\");Q.push(\"61\");Q.push(\"32\");Q.push(\"34\");Q.push(\"37\");Q.push(\"84\");Q.push(\"69\");Q.push(\"77\");Q.push(\"8" ascii
    $s19 = "var cEIGaHTmMiTvU=[];for(nxlCOgE=(-897+897)/870;nxlCOgE<(94980+508)/746;nxlCOgE++){cEIGaHTmMiTvU[nxlCOgE]=String.fromCharCode(nx" ascii
    $s20 = "function KUIqblTtPNgJnFjexEUJyqVjQDRskfRYIBQirBKbaEKTkUctjQXQeR(fpskRLIiTtNlE,KGsfhvQnknNEuy){ return cEIGaHTmMiTvU[VNPHa(fpskRL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}