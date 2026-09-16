rule PEiD_01178_MS_Run_Time_Library_1990__07__ {
  meta:
    description = "[MS Run-Time Library 1990 (07)]"
    ep_only     = "true"

  strings:
    $a = { 2E 8C 1E ?? ?? BB ?? ?? 8E DB 1E E8 ?? ?? 1F 8B 1E ?? ?? 0B DB 74 ?? 8C D1 8B D4 FA 8E D3 BC ?? ?? FB }

  condition:
    $a
}