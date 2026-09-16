rule sig_20160514_a5b0205cbf96bc599c3e7c5912a3ef75 {
  meta:
    description = "datamaliciousorder - file 20160514_a5b0205cbf96bc599c3e7c5912a3ef75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794ae23b50a920e548b48afbc918af890ed6fa6a166392d43698652674b50044"

  strings:
    $s1  = "while (eabn < MZLbkg - (6179 + 1037 - 7214)) {" fullword ascii
    $s2  = "return QgPPInw;" fullword ascii
    $s3  = "function xNBKifo() {" fullword ascii
    $s4  = "function lbFIOg(wkU, PZRZS) {" fullword ascii
    $s5  = "return ENYciav;" fullword ascii
    $s6  = "function vEDP() {" fullword ascii
    $s7  = "function eniSFD() {" fullword ascii
    $s8  = "return PWiwwm;" fullword ascii
    $s9  = "function YbS() {" fullword ascii
    $s10 = "return GEqQq;" fullword ascii
    $s11 = "function xZT() {" fullword ascii
    $s12 = "EtKhOJ = true;" fullword ascii
    $s13 = "function NmuVtLe() {" fullword ascii
    $s14 = "function Oxzii(rtwjdld, kdkndmd) {" fullword ascii
    $s15 = "if (hfDfo(false) == false) {" fullword ascii
    $s16 = "return WxFfrZHW;" fullword ascii
    $s17 = "return gMiT;" fullword ascii
    $s18 = "function FFuTz(tuiyo, fmmd, kemn) {" fullword ascii
    $s19 = "function sbNETp(XVWCWh) {" fullword ascii
    $s20 = "function dNYNqlF(jOQC) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}