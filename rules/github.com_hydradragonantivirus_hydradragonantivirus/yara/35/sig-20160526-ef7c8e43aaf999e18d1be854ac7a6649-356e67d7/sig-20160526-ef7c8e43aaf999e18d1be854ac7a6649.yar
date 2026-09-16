rule sig_20160526_ef7c8e43aaf999e18d1be854ac7a6649 {
  meta:
    description = "datamaliciousorder - file 20160526_ef7c8e43aaf999e18d1be854ac7a6649.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "549c4feefa4e3201395caaa7f4bf1b8e975ed4caa7e2706e47deb8bf9e211c1c"

  strings:
    $s1  = "GjBsbjzStYxgjj);else if (qRDneJsRdhBFoZKjadvIVbE == (932 + Math.round((Math.pow(Math.sin(985), 2) + Math.pow(Math.cos(985), 2) -" ascii
    $s2  = "07), 2) + Math.pow(Math.cos(507), 2) - 1))-868) | lOyUMqtjDRLlwuRhQbGaDo<< (209 + Math.round((Math.pow(Math.sin(247), 2) + Math." ascii
    $s3  = "function DXpveQEfyLzB(xnBhrNjBctQMD) {var mrgoROIyjdtwaRfXf = eyOswyLCZSdw.join(KCCvDffGYbIJoCKCUFxbbk[0]);var rKlyBmVGjBsbjzStY" ascii
    $s4  = "function oatywuhfrsNImRJJkzsrMTHK(HrNoFwqZB,jRTih){return HrNoFwqZB.charAt(jRTih);}" fullword ascii
    $s5  = "function WetEeUjh(ADtVJOsjbKwwXHoDP,kSdNvSglYQloGep){return String.fromCharCode(ADtVJOsjbKwwXHoDP,kSdNvSglYQloGep);}" fullword ascii
    $s6  = " 1))-868)) MhRrMSmPgdYFvjyO += WetEeUjh(rKlyBmVGjBsbjzStYxgjj, NkOJbSj);else MhRrMSmPgdYFvjyO += UoORetjlJnVKYxUjEoFRG(rKlyBmVGj" ascii
    $s7  = "function UoORetjlJnVKYxUjEoFRG(TYPoyfxSaSZNvTvyvi,uJLgKtgVZSYYqlO,adzzRDAdOoJjbKvibyR){return String.fromCharCode(TYPoyfxSaSZNvT" ascii
    $s8  = "function DXpveQEfyLzB(xnBhrNjBctQMD) {var mrgoROIyjdtwaRfXf = eyOswyLCZSdw.join(KCCvDffGYbIJoCKCUFxbbk[0]);var rKlyBmVGjBsbjzStY" ascii
    $s9  = "function LqHsJllniajLKJwCVPVxIoYY(eXTpzmlGzuX,zmIrykWhHyIxbM){return eXTpzmlGzuX.indexOf(zmIrykWhHyIxbM);}" fullword ascii
    $s10 = "function tg(CTYnCgoNDnhOzWA){return String.fromCharCode(CTYnCgoNDnhOzWA);}" fullword ascii
    $s11 = "BsbjzStYxgjj, NkOJbSj, QCpIENVaxvqKUBDMbYAkBbff);} while (mxmzTgxrixxHlZ < xnBhrNjBctQMD.length);return MhRrMSmPgdYFvjyO;}" fullword ascii
    $s12 = "function UoORetjlJnVKYxUjEoFRG(TYPoyfxSaSZNvTvyvi,uJLgKtgVZSYYqlO,adzzRDAdOoJjbKvibyR){return String.fromCharCode(TYPoyfxSaSZNvT" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}