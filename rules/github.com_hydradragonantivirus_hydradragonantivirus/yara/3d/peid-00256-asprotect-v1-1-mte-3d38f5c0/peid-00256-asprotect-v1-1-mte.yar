rule PEiD_00256_ASProtect_v1_1_MTE_ {
  meta:
    description = "[ASProtect v1.1 MTE]"
    ep_only     = "true"

  strings:
    $a = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }

  condition:
    $a
}