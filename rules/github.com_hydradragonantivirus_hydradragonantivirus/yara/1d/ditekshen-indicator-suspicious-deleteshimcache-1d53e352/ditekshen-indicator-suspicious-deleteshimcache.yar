rule DITEKSHEN_INDICATOR_SUSPICIOUS_Deleteshimcache: FILE {
  meta:
    description = "Detects executables embedding anti-forensic artifacts of deleting shim cache"
    author      = "ditekSHen"
    id          = "32b185f2-a11e-522e-822e-7023698975f8"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L2339-L2350"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "4ecd9e4db082a464735e447f95175ec5b35164d42fce7be862400191c143aa23"
    score       = 40
    quality     = 37
    tags        = "FILE"
    importance  = 20

  strings:
    $s1 = "Rundll32.exe apphelp.dll,ShimFlushCache" ascii wide nocase
    $s2 = "Rundll32 apphelp.dll,ShimFlushCache" ascii wide nocase
    $m1 = ".dll,ShimFlushCache" ascii wide nocase
    $m2 = "rundll32" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and (1 of ($s*) or all of ($m*))
}