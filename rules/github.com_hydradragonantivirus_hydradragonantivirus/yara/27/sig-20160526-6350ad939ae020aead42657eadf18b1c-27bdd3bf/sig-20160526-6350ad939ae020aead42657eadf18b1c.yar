rule sig_20160526_6350ad939ae020aead42657eadf18b1c {
  meta:
    description = "datamaliciousorder - file 20160526_6350ad939ae020aead42657eadf18b1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5e1a4572b3de1cd8c1e962aad16f5a43550a91b3e4b59df8bed7b3d62e36188"

  strings:
    $s1  = "function ZSNDGlSztuy(MXsrIpuyCpXAv) {var tgVhUqjrSGGAx = BBsyshS.join(VxAGtbRKewkYvcuWOrbWOj[0]);var SjCIt, JvizcdcLciyJTovCeyIa" ascii
    $s2  = ", 2) - 1))-118)) uRmiAAuSvVgvkmaBrZS += WvBtaTptvoXlTZkwgJ(SjCIt, JvizcdcLciyJTovCeyIav);else uRmiAAuSvVgvkmaBrZS += OLShagsdSkt" ascii
    $s3  = " uRmiAAuSvVgvkmaBrZS += Nm(SjCIt);else if (bTpDQfLIyGl == (182 + Math.round((Math.pow(Math.sin(462), 2) + Math.pow(Math.cos(462)" ascii
    $s4  = "function XKMtyv(hDlgGeTGfsQpocX,VozPCrCtvSJ){return hDlgGeTGfsQpocX.indexOf(VozPCrCtvSJ);}" fullword ascii
    $s5  = "function ttPolPsIoeuNzUDRugDMpUgx(ZaKpzIeoivfhghKJrG,dsLld){return ZaKpzIeoivfhghKJrG.charAt(dsLld);}" fullword ascii
    $s6  = "function ZSNDGlSztuy(MXsrIpuyCpXAv) {var tgVhUqjrSGGAx = BBsyshS.join(VxAGtbRKewkYvcuWOrbWOj[0]);var SjCIt, JvizcdcLciyJTovCeyIa" ascii
    $s7  = "function WvBtaTptvoXlTZkwgJ(eMnyhVwgKuqToHTHMIm,IqiAGcdtFIW){return String.fromCharCode(eMnyhVwgKuqToHTHMIm,IqiAGcdtFIW);}" fullword ascii
    $s8  = "function OLShagsdSktOwTwS(lwgplavvHweFMXFFu,BlVytNHK,oNxcNZhdCtqGBjIH){return String.fromCharCode(lwgplavvHweFMXFFu,BlVytNHK,oNx" ascii
    $s9  = "function Nm(DiutErKosnbARslci){return String.fromCharCode(DiutErKosnbARslci);}" fullword ascii
    $s10 = "function OLShagsdSktOwTwS(lwgplavvHweFMXFFu,BlVytNHK,oNxcNZhdCtqGBjIH){return String.fromCharCode(lwgplavvHweFMXFFu,BlVytNHK,oNx" ascii
    $s11 = "OwTwS(SjCIt, JvizcdcLciyJTovCeyIav, ULrdEBFHulaSuxra);} while (dDYgBUfqQutxgVIbmIsmt < MXsrIpuyCpXAv.length);return uRmiAAuSvVgv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}