rule MAL_BumbleBee_DLL_strings {
  meta:
    description   = "Matches strings found in BumbleBee DLL sample extracted from initial PowerShell loader."
    last_modified = "2024-01-30"
    author        = "@petermstewart"
    DaysofYara    = "30/100"
    sha256        = "39e300a5b4278a3ff5fe48c7fa4bd248779b93bbb6ade55e38b22de5f9d64c3c"

  strings:
    $a1 = "powershell -ep bypass -Command"
    $a2 = " -Command \"Wait-Process -Id "
    $a3 = "schtasks.exe /F /create /sc minute /mo 4 /TN \""
    $a4 = "/ST 04:00 /TR \"wscript /nologo"
    $b1 = "SELECT * FROM Win32_ComputerSystemProduct"
    $b2 = "SELECT * FROM Win32_ComputerSystem"
    $b3 = "SELECT * FROM Win32_OperatingSystem"
    $b4 = "SELECT * FROM Win32_NetworkAdapterConfiguration" wide
    $b5 = "SELECT * FROM Win32_NTEventlogFile" wide
    $b6 = "SELECT * FROM Win32_PnPEntity" wide

  condition:
    uint16(0) == 0x5a4d and
    3 of ($a*) and
    4 of ($b*)
}