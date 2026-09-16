rule sig_20151210_1ad2efc0457eed3afe2873c83083b55f {
  meta:
    description = "datamaliciousorder - file 20151210_1ad2efc0457eed3afe2873c83083b55f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a605e04f1c6dc243f648e8d4741c708d46cfec3f57f1b751589e68c50cb446ff"

  strings:
    $s1  = "function HNOeqNv(jePZUrhXWSjxMMXrAUKDUrnduWPBngbpgpMN) {return !isNaN(parseFloat(jePZUrhXWSjxMMXrAUKDUrnduWPBngbpgpMN)) && isFin" ascii
    $s2  = "function HNOeqNv(jePZUrhXWSjxMMXrAUKDUrnduWPBngbpgpMN) {return !isNaN(parseFloat(jePZUrhXWSjxMMXrAUKDUrnduWPBngbpgpMN)) && isFin" ascii
    $s3  = "function FLtwRRSdjYn(bLxASkjB,lDtvCw){return bLxASkjB.split(lDtvCw)}" fullword ascii
    $s4  = "function erCPU(XkZVRRDeyQj,npaUklAlySKrE,eLnEmBFD){ObXC=parseInt(XkZVRRDeyQj,npaUklAlySKrE);TSLjn=ObXC.toString(eLnEmBFD);return" ascii
    $s5  = "function VtKcFWRrzEDRfsBkfAOSxxQzglGCkgvJnibtqobcYLEFyPBmEyRobt(FraHoQeZrydyr,uWUXNvUxemtvnQ){ return UdRjB[erCPU(FraHoQeZrydyr[" ascii
    $s6  = "TiHcHwRFB[TIizQunoyyO]=(-304+304)/262; while(true) { if(TiHcHwRFB[TIizQunoyyO] > prizH[TIizQunoyyO].length-(196+268)/464) { brea" ascii
    $s7  = "function fEeBChiMRFCBhESbD(prizH){tuEGKhOepSJ= '';for(TIizQunoyyO=(-937+937)/973; TIizQunoyyO < (1433+539)/986; TIizQunoyyO++) {" ascii
    $s8  = " TSLjn;}function cJmsrfuBUmrZTIR(PplmSwSvKLLaQpGgU){eval(PplmSwSvKLLaQpGgU)}" fullword ascii
    $s9  = ";}} return tuEGKhOepSJ}" fullword ascii
    $s10 = "function VtKcFWRrzEDRfsBkfAOSxxQzglGCkgvJnibtqobcYLEFyPBmEyRobt(FraHoQeZrydyr,uWUXNvUxemtvnQ){ return UdRjB[erCPU(FraHoQeZrydyr[" ascii
    $s11 = "function fEeBChiMRFCBhESbD(prizH){tuEGKhOepSJ= '';for(TIizQunoyyO=(-937+937)/973; TIizQunoyyO < (1433+539)/986; TIizQunoyyO++) {" ascii
    $s12 = "function erCPU(XkZVRRDeyQj,npaUklAlySKrE,eLnEmBFD){ObXC=parseInt(XkZVRRDeyQj,npaUklAlySKrE);TSLjn=ObXC.toString(eLnEmBFD);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}