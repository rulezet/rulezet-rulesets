rule PEiD_03555_Zortech_C_v3_0_ {
  meta:
    description = "[Zortech C v3.0]"
    ep_only     = "true"

  strings:
    $a = { FA FC B8 ?? ?? ?? 8C C8 8E D8 }

  condition:
    $a
}