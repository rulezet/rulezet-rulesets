rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_4_2_Virus_Hijac_372 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_1_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ffc22831e7cc7f8347786df680a1e88334870291eaba78062c7ed10ea78b48b"
    hash2       = "774c11fe3a27eac0b4625398b65a1de4e7f3394087ad2330bc27345f36e390a2"
    hash3       = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $x1  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x2  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"470\" Fil=\"\" Fun=\"UnattendLogWV\" Uid=\"33554432\" Msg=\"[sysr" ascii
    $x3  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x4  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"1222\" Fil=\"\" Fun=\"CFinalizeCriticalBoundary::DoExecute\" Uid=" ascii
    $x5  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x6  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x7  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x8  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"0\" Fil=\"\" Fun=\"\" Uid=\"98304\" Msg=\"00004845 (F) Error: Ove" ascii
    $x9  = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"0\" Fil=\"\" Fun=\"\" Uid=\"98304\" Msg=\"00008ffa (F) Error: Ove" ascii
    $x10 = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x11 = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $x12 = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"236\" Fil=\"\" Fun=\"PushButtonReset::Logging::TraceErr\" Uid=\"3" ascii
    $s13 = "<z:row Cls=\"D\" Sev=\"33554432\" Maj=\"Def\" Min=\"Def\" LN=\"215\" Fil=\"\" Fun=\"DoTraceMessage\" Uid=\"33554432\" Msg=\"Copy" ascii
    $s14 = ")WinReIsInstalledOnSystemPartitionInternal() Invalid parameters\" PID=\"308\" TID=\"304\" Con=\"\" Exe=\"X:\\windows\\system32" ascii
    $s15 = "erride collision found under key \\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger\\WiFiSession\\ for val" ascii
    $s16 = "=\"CFinalizeCriticalBoundary::DoExecute: Rollback in system context will not be registered.\" PID=\"308\" TID=\"304\" Con=\"\" E" ascii
    $s17 = "x80070003 in PbrGetRestoreToBaselineVal (base\\reset\\engine\\scenario\\src\\sensetargetos.cpp:61): Does not find registry key o" ascii
    $s18 = "x80070005 in PushButtonReset::File::Delete (base\\reset\\util\\src\\filesystem.cpp:3260): Failed to delete [\\\\?\\C:\\Windows.o" ascii
    $s19 = "x80070020 in PushButtonReset::File::Copy (base\\reset\\util\\src\\filesystem.cpp:3053): Failed to copy [\\\\?\\C:\\Windows.old" ascii
    $s20 = "race-Tel-Merge.etl, C:\\$WINDOWS.~BT\\Sources\\Panther\\SysResetTrace-Tel-Merge.etl) failed. Error: 0x00000003\" PID=\"308\" TID" ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}