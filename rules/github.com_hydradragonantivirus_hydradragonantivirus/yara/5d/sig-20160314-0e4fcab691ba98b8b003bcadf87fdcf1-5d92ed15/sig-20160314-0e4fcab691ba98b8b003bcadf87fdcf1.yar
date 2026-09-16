rule sig_20160314_0e4fcab691ba98b8b003bcadf87fdcf1 {
  meta:
    description = "datamaliciousorder - file 20160314_0e4fcab691ba98b8b003bcadf87fdcf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5707eed3eada099977d6df18cf83f255e3e878a00cf932f9ae5637c279542eca"

  strings:
    $s1 = "aNZjXUuXdCCmvck.open(ARKjpCnGvaqia, QjSH + GPBccY + fpTPANhBrj + nXuBUJcHqFLIRH + jUT + JFUxIbPYtPjejS + hts + inPPD + IalQzoWk " ascii
    $s2 = "while (aNZjXUuXdCCmvck.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "+ ukAibWCnNe + pTivMQSQBNoM + jOOgQJ + xROchLqJtMWTXpA, false);" fullword ascii
    $s4 = "return YUZTrbXWAFpqjIY + hKhbfV + rfHuVUOJ + EJoDFLMca + MjkJkkajDUa + kdnDWUb + CyTvr" fullword ascii
    $s5 = "function Kumshnh(fname)" fullword ascii
    $s6 = "function qlARK(n)" fullword ascii
    $s7 = "var dzAoNdDofAGpnc = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}