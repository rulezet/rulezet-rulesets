rule PEiD_01433_ORiEN_V2_12____Fisun_A_V__ {
  meta:
    description = "[ORiEN V2.12 -> Fisun A.V.]"
    ep_only     = "true"

  strings:
    $a = { E9 5D 01 00 00 CE D1 CE CD 0D }

  condition:
    $a
}