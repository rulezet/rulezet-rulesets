rule PEiD_00958_kkrunchy_0_23_alpha_2____Ryd_ {
  meta:
    description = "[kkrunchy 0.23 alpha 2 -> Ryd]"
    ep_only     = "true"

  strings:
    $a = { BD ?? ?? ?? ?? C7 45 00 ?? ?? ?? 00 B8 ?? ?? ?? 00 89 45 04 89 45 54 50 C7 45 10 ?? ?? ?? 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }

  condition:
    $a
}