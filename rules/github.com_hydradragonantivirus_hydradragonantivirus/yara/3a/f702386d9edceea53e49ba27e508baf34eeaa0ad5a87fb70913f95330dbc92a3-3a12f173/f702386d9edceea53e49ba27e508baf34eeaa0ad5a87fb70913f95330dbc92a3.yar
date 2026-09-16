rule f702386d9edceea53e49ba27e508baf34eeaa0ad5a87fb70913f95330dbc92a3 {
  meta:
    description = "datamaliciousorder - file f702386d9edceea53e49ba27e508baf34eeaa0ad5a87fb70913f95330dbc92a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f702386d9edceea53e49ba27e508baf34eeaa0ad5a87fb70913f95330dbc92a3"

  strings:
    $x1  = "ArlingtonArea.Run('cmd /c ' + PortlandPlace, 0, true);" fullword ascii
    $s2  = "El_PasoParkway.WriteLine(\"%bhytployk%i%bhytployk%f%bhytployk% %bhytployk%n%bhytployk%o%bhytployk%t %bhytployk%D%bhytployk%E%bhy" ascii
    $s3  = "ytployk%r%bhytployk%t%bhytployk% \\\"\\\" /min \\\"%~dpnx0\\\" %* & exit)\");" fullword ascii
    $s4  = "gibe%a%vegsgibe%u%vegsgibe%q%vegsgibe%i%vegsgibe%g=gBiAHIAagibgenBsACwAW\\\"\");" fullword ascii
    $s5  = "ryfx%r%eriuryfx%a%eriuryfx%q%eriuryfx%o%eriuryfx%y=tring([Convert]::From\\\"\");" fullword ascii
    $s6  = "El_PasoParkway.WriteLine(\"!jgkxmdwxqpysdks! \\\"%eriuryfx%y%eriuryfx%w%eriuryfx%z%eriuryfx%m%eriuryfx%p%eriuryfx%o%eriuryfx%v%e" ascii
    $s7  = "El_PasoParkway.WriteLine(\"!jgkxmdwxqpysdks! \\\"%loukjhuv%g%loukjhuv%h%loukjhuv%p%loukjhuv%c%loukjhuv%k%loukjhuv%c%loukjhuv%d%l" ascii
    $s8  = "grit%v%mrecgrit%g%mrecgrit%o%mrecgrit%b%mrecgrit%h=AFsAibgenUwB5AHMAdABl\\\"\");" fullword ascii
    $s9  = "kiyi%p%kdobkiyi%r%kdobkiyi%b%kdobkiyi%n%kdobkiyi%y=ZAGsibgenANABsAEsAZgB\\\"\");" fullword ascii
    $s10 = "var El_PasoParkway = NashvilleBoulevard.CreateTextFile(PortlandPlace, true);" fullword ascii
    $s11 = "khir%c%dxztkhir%o%dxztkhir%j%dxztkhir%x%dxztkhir%h=AIAAgACAibgenAIAAkAHM\\\"\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}