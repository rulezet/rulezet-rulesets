rule sig_20151210_76549cab869d189a3df7c536684b0835 {
  meta:
    description = "datamaliciousorder - file 20151210_76549cab869d189a3df7c536684b0835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0310930a39b795dd054215311fe1e2c4034d5cab02ec138c6785cc9e8559a394"

  strings:
    $s1  = "function wBjUdpS(bbGggjXxKroqRdAKECvCuJHdSpOcmmdkcWCv) {return !isNaN(parseFloat(bbGggjXxKroqRdAKECvCuJHdSpOcmmdkcWCv)) && isFin" ascii
    $s2  = "function wBjUdpS(bbGggjXxKroqRdAKECvCuJHdSpOcmmdkcWCv) {return !isNaN(parseFloat(bbGggjXxKroqRdAKECvCuJHdSpOcmmdkcWCv)) && isFin" ascii
    $s3  = "function JPEMQQjlxKc(atLoPZxI,gPTujk){return atLoPZxI.split(gPTujk)}" fullword ascii
    $s4  = "FPgQQoE[wzCuDjdJdzx]=(-836+836)/273; while(true) { if(CrFPgQQoE[wzCuDjdJdzx] > vWhss[wzCuDjdJdzx].length-(247+101)/348) { break;" ascii
    $s5  = "function EYVda(KRDrLBQkHRX,KXIVSLTlCJted,iWgwMrUb){lRGF=parseInt(KRDrLBQkHRX,KXIVSLTlCJted);onQRL=lRGF.toString(iWgwMrUb);return" ascii
    $s6  = "}} return NZbRwIZpvqP}" fullword ascii
    $s7  = "function EYVda(KRDrLBQkHRX,KXIVSLTlCJted,iWgwMrUb){lRGF=parseInt(KRDrLBQkHRX,KXIVSLTlCJted);onQRL=lRGF.toString(iWgwMrUb);return" ascii
    $s8  = " onQRL;}function UpOFLwRivlBuDnI(dLelJPSNQgPVuMHKP){eval(dLelJPSNQgPVuMHKP)}" fullword ascii
    $s9  = "function OXTmFjXGPWhjuPznd(vWhss){NZbRwIZpvqP= '';for(wzCuDjdJdzx=(-113+113)/320; wzCuDjdJdzx < (-520+538)/9; wzCuDjdJdzx++) {Cr" ascii
    $s10 = "function AvGBhTpddcTaXGOCnLoavpzlCaMfvxYVQaYAOSQVcfwzGkdQWJanmQ(iOBEOtKlpxYaZ,eNzSuRfQruIzvT){ return FOxEp[EYVda(iOBEOtKlpxYaZ[" ascii
    $s11 = "function OXTmFjXGPWhjuPznd(vWhss){NZbRwIZpvqP= '';for(wzCuDjdJdzx=(-113+113)/320; wzCuDjdJdzx < (-520+538)/9; wzCuDjdJdzx++) {Cr" ascii
    $s12 = "function AvGBhTpddcTaXGOCnLoavpzlCaMfvxYVQaYAOSQVcfwzGkdQWJanmQ(iOBEOtKlpxYaZ,eNzSuRfQruIzvT){ return FOxEp[EYVda(iOBEOtKlpxYaZ[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}