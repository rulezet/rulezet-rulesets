rule PEiD_01785_PROTECT__EXE_COM_v6_0_ {
  meta:
    description = "[PROTECT! EXE/COM v6.0]"
    ep_only     = "true"

  strings:
    $a = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }

  condition:
    $a
}