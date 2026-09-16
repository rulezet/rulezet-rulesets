rule sig_20160513_342ad341801b229f771ecf335c45ca34 {
  meta:
    description = "datamaliciousorder - file 20160513_342ad341801b229f771ecf335c45ca34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9688a21040bee2273e288f1a80b8d8318193e0461cd5e7ad6254d222c9c8705"

  strings:
    $s1  = "while (gbdap < eOomTEk - (7690 - 7688)) {" fullword ascii
    $s2  = "function FveuUg() {" fullword ascii
    $s3  = "function ANh() {" fullword ascii
    $s4  = "function NxF() {" fullword ascii
    $s5  = "function aZO() {" fullword ascii
    $s6  = "return wuHRdf;" fullword ascii
    $s7  = "function bsIzj() {" fullword ascii
    $s8  = "return zhQzTw;" fullword ascii
    $s9  = "function PcYHs(tuiyo, fmmd, kemn) {" fullword ascii
    $s10 = "function Obtc() {" fullword ascii
    $s11 = "var tGxNMwt = false;" fullword ascii
    $s12 = "function QCojO(rtwjdld, kdkndmd) {" fullword ascii
    $s13 = "return CdklHQr;" fullword ascii
    $s14 = "function dsAfHf() {" fullword ascii
    $s15 = "if (aYVSj == false) {" fullword ascii
    $s16 = "function xRpq(TRzHpDZs) {" fullword ascii
    $s17 = "var RjqBB = false;" fullword ascii
    $s18 = "return Ryes;" fullword ascii
    $s19 = "function KboYya(zSvg) {" fullword ascii
    $s20 = "return UbDSIW;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}