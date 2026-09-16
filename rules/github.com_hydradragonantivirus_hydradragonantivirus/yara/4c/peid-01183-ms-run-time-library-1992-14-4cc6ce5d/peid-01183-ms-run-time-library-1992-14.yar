rule PEiD_01183_MS_Run_Time_Library_1992__14__ {
  meta:
    description = "[MS Run-Time Library 1992 (14)]"
    ep_only     = "true"

  strings:
    $a = { 1E 06 8C C8 8E D8 8C C0 A3 ?? ?? 83 C0 ?? A3 ?? ?? B4 30 }

  condition:
    $a
}