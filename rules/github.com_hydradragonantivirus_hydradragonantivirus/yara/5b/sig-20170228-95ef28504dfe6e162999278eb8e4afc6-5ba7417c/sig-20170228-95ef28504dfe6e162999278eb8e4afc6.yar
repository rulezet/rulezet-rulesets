rule sig_20170228_95ef28504dfe6e162999278eb8e4afc6 {
  meta:
    description = "datamaliciousorder - file 20170228_95ef28504dfe6e162999278eb8e4afc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47357dc824daba0119f4bb35f6f7c5914572417bbe21d8ad5069181974808032"

  strings:
    $x1  = "return [Number.NaN, \"cmd.exe /c \\\"powershell  $\", Number.NaN, Number.NaN];" fullword ascii
    $s2  = "return [Number.NaN, Number.NaN, \"WScript.Shell\", Number.NaN];" fullword ascii
    $s3  = "return [Number.NaN, Number.NaN, \"Scripting.FileSystemObjec\", Number.NaN];" fullword ascii
    $s4  = "return [Number.NaN, \"if(mist.GetBaseName('C:')\", Number.NaN];" fullword ascii
    $s5  = "if ([new[upjexuzq, Number.NaN][0](olotowh(1)[1] + ilobo(1)[1] + ivax(1)[1] + mvyqdyq(1)[0] + togmo(1)[0])(), Number.NaN, Number." ascii
    $s6  = "return [Number.NaN, \" === '' && typeof mist.Ge\"];" fullword ascii
    $s7  = "return [Number.NaN, \"run\", Number.NaN, Number.NaN];" fullword ascii
    $s8  = "var mist = fquvucy[2][ihxopy(1)[1]](miwaco(1)[2] + ucuzohb(1)[0]);" fullword ascii
    $s9  = "return [Number.NaN, \"CreateObject\", Number.NaN, Number.NaN];" fullword ascii
    $s10 = "return [\"g') return true; else ret\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s11 = "return [\"+$ntudu+$rypo+$wisy+$odsy\", Number.NaN, Number.NaN];" fullword ascii
    $s12 = "return [\"urn false;\", Number.NaN, Number.NaN, Number.NaN];" fullword ascii
    $s13 = "return [\"$idowxo+$qefhipj+$zxycti+\", Number.NaN];" fullword ascii
    $s14 = "return [Number.NaN, \"$soswa='^lic';$izarwo='^e\"];" fullword ascii
    $s15 = "return [Number.NaN, \"cuch='^Pro';$ktomtegb='^,\"];" fullword ascii
    $s16 = "return [Number.NaN, \"csovi='^hop';$qamebf='^-E\"];" fullword ascii
    $s17 = "return [\"x';$yhuv='^.ex';$semqux='\", Number.NaN, Number.NaN];" fullword ascii
    $s18 = "return [Number.NaN, Number.NaN, \"='^sec'; Invoke-Expressio\"];" fullword ascii
    $s19 = "return [Number.NaN, Number.NaN, \"gb+$jagta+$dazno+$ixalva+\"];" fullword ascii
    $s20 = "return [Number.NaN, \"ymolf+$ukqimo+$zezlihd+$s\", Number.NaN, Number.NaN];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}