rule sig_20170228_91ca301e98e7c699ee9d5eb08b65b67e {
  meta:
    description = "datamaliciousorder - file 20170228_91ca301e98e7c699ee9d5eb08b65b67e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abbe2b346c05022426bd40d86e500b9cf4bcbbccbc90af75d06b8778dd19f01c"

  strings:
    $x1  = "return [\"cmd.exe /c \\\"powershell  $\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s2  = "return [Number.NaN, Number.NaN, \"WScript.Shell\"];" fullword ascii
    $s3  = "return [\"Scripting.FileSystemObjec\", Number.NaN];" fullword ascii
    $s4  = "return [\"if(mist.GetBaseName('C:')\", Number.NaN, Number.NaN];" fullword ascii
    $s5  = "return [\"run\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s6  = "return [Number.NaN, \" === '' && typeof mist.Ge\"];" fullword ascii
    $s7  = "var mist = oracxi[2][bnukura(1)[1]](tdazkupci(1)[0] + uclinqobh(1)[1]);" fullword ascii
    $s8  = "ek(1)[2] + xtowu(1)[0] + enxusuh(1)[0] + sera(1)[1] + cravxyk(1)[2] + qazoc(1)[0] + puddisk(1)[2] + gerji(1)[1] + jgicputy(1)[0]" ascii
    $s9  = "return [Number.NaN, Number.NaN, Number.NaN, \"tBaseName('C:') == 'strin\"];" fullword ascii
    $s10 = "return [Number.NaN, \"ow+$dannu+$ahut+$hempold+\"];" fullword ascii
    $s11 = "return [Number.NaN, \"io';$olvucku='^own'; Invo\", Number.NaN, Number.NaN];" fullword ascii
    $s12 = "return [\"+$rvokud+$kpagxi+$ejeh+$e\", Number.NaN];" fullword ascii
    $s13 = "return [Number.NaN, Number.NaN, \"jo='^ypa';$mdyxajc='^Obj'\"];" fullword ascii
    $s14 = "return [\"g') return true; else ret\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s15 = "return [Number.NaN, Number.NaN, \".e';$eviz='^env';$qakhi='\"];" fullword ascii
    $s16 = "return [Number.NaN, \"$kaxy='^ecu';$igryvpi='^e\", Number.NaN];" fullword ascii
    $s17 = "return [\"+$otmeld+$ocvym+$cojmiqx+\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s18 = "return [\"ryhb+$ijas);\\\"\", Number.NaN, Number.NaN];" fullword ascii
    $s19 = "return [\"^ect';$kpagxi='^ces';$ufz\", Number.NaN];" fullword ascii
    $s20 = "return [Number.NaN, Number.NaN, \"$ubjyjy='^nPo';$huhu='^ S\"];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}