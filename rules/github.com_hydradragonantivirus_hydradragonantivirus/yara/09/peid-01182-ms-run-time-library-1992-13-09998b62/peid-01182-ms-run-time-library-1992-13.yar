rule PEiD_01182_MS_Run_Time_Library_1992__13__ {
  meta:
    description = "[MS Run-Time Library 1992 (13)]"
    ep_only     = "true"

  strings:
    $a = { BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB 33 DB B8 ?? ?? CD 21 }

  condition:
    $a
}