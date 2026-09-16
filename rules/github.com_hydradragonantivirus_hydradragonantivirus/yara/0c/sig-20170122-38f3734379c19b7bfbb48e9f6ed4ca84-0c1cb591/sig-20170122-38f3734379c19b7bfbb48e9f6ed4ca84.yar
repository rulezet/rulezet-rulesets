rule sig_20170122_38f3734379c19b7bfbb48e9f6ed4ca84 {
  meta:
    description = "datamaliciousorder - file 20170122_38f3734379c19b7bfbb48e9f6ed4ca84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "decd46caa47ecb8e6c6c56cbce98db4becad3721c077d45e5f8bdb94efb6790f"

  strings:
    $x1  = "var lruhan = \"cmd.exe /c \" + etzyx + \"  $ujitq='^nv:temp+''\\eje';$jqohilp='^Policy     Bypass';$oflehi='^h';$nacqyb='^jpoqw." ascii
    $x2  = "var lruhan = \"cmd.exe /c \" + etzyx + \"  $ujitq='^nv:temp+''\\eje';$jqohilp='^Policy     Bypass';$oflehi='^h';$nacqyb='^jpoqw." ascii
    $s3  = "');(';$ruxym='^/outloo.exe'',';$igmycte='^stem.Net.Webc';$aqila='^New-Object Sy';$aheh='^$path); Start';$ihudb='^ss; $path=($e';" ascii
    $s4  = "function fnebqoc() {" fullword ascii
    $s5  = "function rlagnozfom() {" fullword ascii
    $s6  = "var owyzorn = null;" fullword ascii
    $s7  = "var ynpeqve = null;" fullword ascii
    $s8  = "var zkimfulvezco = null;" fullword ascii
    $s9  = "return kemofitx;" fullword ascii
    $s10 = "var ltiwcutj = null;" fullword ascii
    $s11 = "function sunvalpetcu() {" fullword ascii
    $s12 = "return ennuzigy;" fullword ascii
    $s13 = "var injygu = null;" fullword ascii
    $s14 = "var ejupigj = typeof navigator;" fullword ascii
    $s15 = "var ymerjo = undefined;" fullword ascii
    $s16 = "if (sunvalpetcu() === undefined) {" fullword ascii
    $s17 = "return 109.6446;" fullword ascii
    $s18 = "switch (dfevmirm()) {" fullword ascii
    $s19 = "var ujyho = null;" fullword ascii
    $s20 = "if (cyhbir() === undefined) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}