rule sig_20160514_2d08a4505c624ea2e0139e02f80da3dc {
  meta:
    description = "datamaliciousorder - file 20160514_2d08a4505c624ea2e0139e02f80da3dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5f84447232e7b308fdd9a621735f92adfb8093d58b582fd1dd18797c26b13c3"

  strings:
    $s1  = "while (FHEgOdW < ZUkQmwAX - (1731 + 1312 - 3041)) {" fullword ascii
    $s2  = "var FvjVVVc = true;" fullword ascii
    $s3  = "return ciQfzwai;" fullword ascii
    $s4  = "return HjmHmu;" fullword ascii
    $s5  = "return XStJScy;" fullword ascii
    $s6  = "function BnwcM() {" fullword ascii
    $s7  = "return hoYWEvbl;" fullword ascii
    $s8  = "function Xoy() {" fullword ascii
    $s9  = "if (yhRgL === true) {" fullword ascii
    $s10 = "if (nqdpr === false) {" fullword ascii
    $s11 = "function SxcBQGk() {" fullword ascii
    $s12 = "return SyjWvA;" fullword ascii
    $s13 = "function RztHMZI(gvSb) {" fullword ascii
    $s14 = "function feM(tuiyo, fmmd, kemn) {" fullword ascii
    $s15 = "return sUTtcj;" fullword ascii
    $s16 = "return FuqB;" fullword ascii
    $s17 = "function QyQpg(SmsmlU, IiG) {" fullword ascii
    $s18 = "var OLLuN = true;" fullword ascii
    $s19 = "function ZCdboa() {" fullword ascii
    $s20 = "return riceCXUB;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}