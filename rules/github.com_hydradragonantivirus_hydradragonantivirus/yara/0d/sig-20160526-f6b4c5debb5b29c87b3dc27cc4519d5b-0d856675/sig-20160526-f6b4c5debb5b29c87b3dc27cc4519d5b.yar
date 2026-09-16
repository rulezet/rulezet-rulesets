rule sig_20160526_f6b4c5debb5b29c87b3dc27cc4519d5b {
  meta:
    description = "datamaliciousorder - file 20160526_f6b4c5debb5b29c87b3dc27cc4519d5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b3cdad121e07b18e29c2b0eaa2b8cc18b34e342c50adc64101e5f5d2481751"

  strings:
    $s1  = "h.pow(Math.sin(551), 2) + Math.pow(Math.cos(551), 2) - 1))-36) & 0xff;aeiXTrkyiZpzE = jjUmrmymTdapAItn>> (138 + Math.round((Math" ascii
    $s2  = "function mTSsw(uodvCLzJJBXay) {var EnfcrHiDXgpRIdoOxOomXzxX = dSKBOQR.join(dgSMDBwaKX[0]);var LYjHgcIBSbanKrB, aeiXTrkyiZpzE, Qf" ascii
    $s3  = "88 + Math.round((Math.pow(Math.sin(845), 2) + Math.pow(Math.cos(845), 2) - 1))-724)) ndIOSscOnwRoj += xs(LYjHgcIBSbanKrB);else i" ascii
    $s4  = "function rIHCZfZzZ(QASfhioLnqTgmWmFj,KVSAKJZXYCjGsKRIkBieogn){return QASfhioLnqTgmWmFj.charAt(KVSAKJZXYCjGsKRIkBieogn);}" fullword ascii
    $s5  = "a(LYjHgcIBSbanKrB, aeiXTrkyiZpzE);else ndIOSscOnwRoj += JHrFGogEfC(LYjHgcIBSbanKrB, aeiXTrkyiZpzE, QfWvseRv);} while (OjUfKgsdnv" ascii
    $s6  = "function mTSsw(uodvCLzJJBXay) {var EnfcrHiDXgpRIdoOxOomXzxX = dSKBOQR.join(dgSMDBwaKX[0]);var LYjHgcIBSbanKrB, aeiXTrkyiZpzE, Qf" ascii
    $s7  = "D < uodvCLzJJBXay.length);return ndIOSscOnwRoj;}" fullword ascii
    $s8  = "function JHrFGogEfC(GWKayxZsDFlg,QoXYy,lusIwCtBWYRRPlxUhI){return String.fromCharCode(GWKayxZsDFlg,QoXYy,lusIwCtBWYRRPlxUhI);}" fullword ascii
    $s9  = "function QpoRBGWpXyKvpOELW(LsobNiroF,WXcKIRBSYyzencdFark){return LsobNiroF.indexOf(WXcKIRBSYyzencdFark);}" fullword ascii
    $s10 = "function EREvLxxUxcea(IpvrhvlDpz,ujVdJoZxMKVdxpecGG){return String.fromCharCode(IpvrhvlDpz,ujVdJoZxMKVdxpecGG);}" fullword ascii
    $s11 = "function xs(TSuyccckuUJRaBoD){return String.fromCharCode(TSuyccckuUJRaBoD);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}