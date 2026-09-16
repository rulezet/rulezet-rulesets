rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113_1_Virus_Hija_364 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d1b509451f00201266d1ca734cf8ae37fdeeedde7a1a4550e0750e9e3316a8"
    hash2       = "3112ee48980ee355e436b9f1f525b69c09d522fd26edd28acb64066bd24a57a0"
    hash3       = "660abb9fe016d15a4064be6ed8a9c3dddb3ae71c06d80f8b5e32d0c471fc1dc3"
    hash4       = "c39ed073ecc4cb372eedb12da81184d440c6eb2e2be1e3fc8b731ad43355717e"
    hash5       = "906c9e4e5ab33e9c806bf6d599c20c12a923b135167ae404a119876bfdae42ab"
    hash6       = "0020b5f10333813bb3ba921bf702cd6ec4f9f7631c53e948ca0710d14cd55e34"

  strings:
    $x1  = "  = Process: C:\\Windows\\system32\\svchost.exe" fullword ascii
    $x2  = "  = Module: C:\\Windows\\system32\\wuaueng.dll" fullword ascii
    $x3  = "  = Module: c:\\windows\\system32\\wuaueng.dll" fullword ascii
    $x4  = "  = Process: C:\\Windows\\system32\\wuauclt.exe" fullword ascii
    $s5  = "  * Target group: (Unassigned Computers)" fullword ascii
    $s6  = "  # Will interact with non-admins (Non-admins are elevated (User preference))" fullword ascii
    $s7  = "  - Install call complete (succeeded = 1, succeeded with errors = 0, failed = 0, unaccounted = 0)" fullword ascii
    $s8  = "***********  Agent: Initializing Windows Update Agent  ***********" fullword ascii
    $s9  = "<<-- SUBMITTED -- COMAPI: Search [ClientId = wusa]" fullword ascii
    $s10 = "--  END  --  COMAPI: Search [ClientId = wusa]" fullword ascii
    $s11 = "-- START --  COMAPI: Install [ClientId = wusa]" fullword ascii
    $s12 = "**  END  **  Service: Service exit [Exit code = 0x240001]" fullword ascii
    $s13 = ">>--  RESUMED  -- COMAPI: Search [ClientId = wusa]" fullword ascii
    $s14 = "***********  Report: Initializing static reporting data  ***********" fullword ascii
    $s15 = "-- START --  COMAPI: Search [ClientId = wusa]" fullword ascii
    $s16 = "<<-- SUBMITTED -- COMAPI: Install [ClientId = wusa]" fullword ascii
    $s17 = "** START **  Service: Service startup" fullword ascii
    $s18 = ">>--  RESUMED  -- COMAPI: Install [ClientId = wusa]" fullword ascii
    $s19 = "--  END  --  COMAPI: Install [ClientId = wusa]" fullword ascii
    $s20 = "  * Online = Yes; Ignore download priority = No" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}