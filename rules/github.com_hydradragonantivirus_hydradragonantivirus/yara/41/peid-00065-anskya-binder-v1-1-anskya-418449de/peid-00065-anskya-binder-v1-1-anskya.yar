rule PEiD_00065_Anskya_Binder_v1_1____Anskya_ {
  meta:
    description = "[Anskya Binder v1.1 -> Anskya]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

  condition:
    $a
}