rule PEiD_01014_MetaWare_High_C_Run_Time_Library___Phar_Lap_DOS_Extender_1983_89_ {
  meta:
    description = "[MetaWare High C Run-Time Library + Phar Lap DOS Extender 1983-89]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 50 B8 ?? ?? 50 CB }

  condition:
    $a
}