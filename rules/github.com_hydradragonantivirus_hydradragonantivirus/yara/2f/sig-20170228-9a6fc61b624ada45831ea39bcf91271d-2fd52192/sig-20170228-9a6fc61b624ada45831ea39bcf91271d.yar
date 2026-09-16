rule sig_20170228_9a6fc61b624ada45831ea39bcf91271d {
  meta:
    description = "datamaliciousorder - file 20170228_9a6fc61b624ada45831ea39bcf91271d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cb37f58e619ce91dbf444bfb59b98fbf3a50490b912db2f3bfb40442c313079"

  strings:
    $x1  = "return [Number.NaN, \"cmd.exe /c \\\"powershell  $\", Number.NaN];" fullword ascii
    $s2  = "return [\"WScript.Shell\", Number.NaN];" fullword ascii
    $s3  = "return [Number.NaN, \"Scripting.FileSystemObjec\", Number.NaN, Number.NaN];" fullword ascii
    $s4  = "return [\"if(mist.GetBaseName('C:')\", Number.NaN];" fullword ascii
    $s5  = "return [Number.NaN, Number.NaN, \" === '' && typeof mist.Ge\"];" fullword ascii
    $s6  = "return [Number.NaN, \"run\"];" fullword ascii
    $s7  = "//var mist = wtypxa[2][pgyjugs(1)[2]](gixidv(1)[1] + alydwydx(1)[0]);" fullword ascii
    $s8  = "return [\"urn false;\", Number.NaN];" fullword ascii
    $s9  = "return [Number.NaN, Number.NaN, \"^xe''';$fyqcy='^tps';$rpo\"];" fullword ascii
    $s10 = "return [Number.NaN, Number.NaN, \"CreateObject\", Number.NaN];" fullword ascii
    $s11 = "return [Number.NaN, Number.NaN, \";$updafhe='^ste';$ejelge=\", Number.NaN];" fullword ascii
    $s12 = "return [Number.NaN, \"ebb+$idocn+$ywnysz+$jarta\"];" fullword ascii
    $s13 = "return [\"psawobf+$rpofnu+$cpaqyl+$\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s14 = "return [\"t\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s15 = "var vzagy = [Number.NaN, Function][1];" fullword ascii
    $s16 = "return [Number.NaN, Number.NaN, \"='^Obj';$lpaziht='^ect';$\", Number.NaN];" fullword ascii
    $s17 = "return [\"'^ath';$rytnihk='^ope';$e\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s18 = "return [\"c';$esborcy='^own';$qeqli\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s19 = "return [Number.NaN, \");\\\"\"];" fullword ascii
    $s20 = "return [\"stindoz='^''ht';$ukjemt='\", Number.NaN, Number.NaN];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}