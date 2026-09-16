rule P2PinfectBash {
  meta:
    author = "nbill@cadosecurity.com"
    description = "Detects P2Pinfect bash payload"
  strings:
    $h1 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 0A 59 E8 17 6C 01 00 84 C0 0F 85 0F 03 00 00 }
    $h2 = { 48 8B 9C 24 ?? ?? 00 00 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 09 59 E8 34 6C 01 00 84 C0 0F 85 AC 02 00 00 }
    $h3 = { 4C 89 EF 48 89 DE 48 8D 15 ?? ?? ?? 00 6A 03 59 E8 DD 6B 01 00 84 C0 0F 85 DF 03 00 00 }
  condition:
    uint16(0) == 0x457f and all of them
}