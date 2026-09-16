rule sig_20160525_d22014968423d30716b00e8b89b6cc38 {
  meta:
    description = "datamaliciousorder - file 20160525_d22014968423d30716b00e8b89b6cc38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86a12b200091881a53f52820e44e8cb8ca89392b92d48008f3cc69827335e3ae"

  strings:
    $s1 = "loch noitcnuf([rerednera[rerednera = /*  Axy KKa IlC */ sdnet rav" fullword ascii
    $s2 = "\"56x\\\\T\" = eixodo rav\\n;\"47x\\\\x\" = gsmo rav;};gedotdaro nruter{)gedotdaro(mo noitcnuf;};dnenoisilloco nruter{)dnenoisil" ascii
    $s3 = "rapt + ))(};gsmt nruter{)(mt noitcnuf([eixodb    \\n;)(])deerdi(reredneri + )modnari(tsilslianbmuhtoi[eixodb    \\n         ;mb " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}