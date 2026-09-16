rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_4_2_Virus_Hijac_231 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_13_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_41.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cd2a3f2ab58ceba304b685d80ec99cee98293281f554f4b247bc9ab5043880d"
    hash2       = "ea98f7689c0417e440e1d27c4cbc44d8e94698ae907024685b374f0a2f431ced"
    hash3       = "aed769307e38ba23233c9e5bd676f009bcc5871cc4f6dd1447e662ca109bd72d"
    hash4       = "379fa155bfa927347e6d6da7a3949837c9bd7fb80119359f8045ef0bfcda3eeb"
    hash5       = "3a0f644cb37624ab9f60b7e6706582255a016628c8c78c94d829ecc3ac9429f6"
    hash6       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash7       = "50352927df7d25fd238015087b304fbb5a4180ac8743ad9462c9e726535e996a"
    hash8       = "64d7be253b0683466635cb9ccab39bee55c812e9330814b6ce3a44039ddb5ef5"
    hash9       = "bb54c0b4b5f9b5ebe24d3a95ca2c5a237d65193c6f4901d4969ead3b60a684e4"
    hash10      = "c47d2baf377420863029283acb7f69d110fe7c2387caa25e3365126e3e4a7495"
    hash11      = "90fdc7a6f770c7e572f89c673657056b2648afb25355cea6519bf38088d76175"
    hash12      = "67ef84dfef19e55a6c230a10a42f614fe523d062ea7f152c7a31b30b4f4a31ff"
    hash13      = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $x1  = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExW\",\"FAILURE\",\"\",\"hKey->HKEY_LOCAL_MACHIN" ascii
    $x2  = "tware\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\HelpMe.exe\\RpcThreadPoolThrottle\"" fullword ascii
    $s3  = "\"20200703104936.750\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExA\",\"FAILURE\",\"\",\"hKey->HKEY_CURRENT_USER" ascii
    $s4  = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"synchronization\",\"CreateMutexW\",\"SUCCESS\",\"0x000000e0\",\"lpName-" ascii
    $s5  = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"synchronization\",\"CreateMutexW\",\"SUCCESS\",\"0x00000090\",\"lpName-" ascii
    $s6  = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"synchronization\",\"CreateMutexW\",\"SUCCESS\",\"0x000000e8\",\"lpName-" ascii
    $s7  = "\"20200703104936.820\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x0000011c\"," ascii
    $s8  = "\"20200703104936.820\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x0000011c\",\"hKey->0x00000" ascii
    $s9  = "\"20200703104936.820\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegOpenKeyExW\",\"SUCCESS\",\"0x00000116\",\"hKey->0x00000" ascii
    $s10 = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x00000090\"," ascii
    $s11 = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"FAILURE\",\"\",\"hKey->0x00000090\"," ascii
    $s12 = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x000000d8\"," ascii
    $s13 = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x00000092\"," ascii
    $s14 = "\"20200703104936.800\",\"1836\",\"HelpMe.exe\",\"824\",\"registry\",\"RegQueryValueExW\",\"SUCCESS\",\"\",\"hKey->0x00000092\"," ascii
    $s15 = "null)\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}