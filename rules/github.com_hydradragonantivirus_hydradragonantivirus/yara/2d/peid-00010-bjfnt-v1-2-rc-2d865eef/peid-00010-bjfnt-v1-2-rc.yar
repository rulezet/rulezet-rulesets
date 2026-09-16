rule PEiD_00010__BJFnt_v1_2_RC_ {
  meta:
    description = "[.BJFnt v1.2 RC]"
    ep_only     = "true"

  strings:
    $a = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }

  condition:
    $a
}