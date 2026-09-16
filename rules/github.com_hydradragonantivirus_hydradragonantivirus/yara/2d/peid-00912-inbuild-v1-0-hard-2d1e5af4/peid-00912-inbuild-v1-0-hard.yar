rule PEiD_00912_Inbuild_v1_0__hard_ {
  meta:
    description = "[Inbuild v1.0 [hard]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? BB ?? ?? 2E ?? ?? 2E ?? ?? 43 E2 }

  condition:
    $a
}