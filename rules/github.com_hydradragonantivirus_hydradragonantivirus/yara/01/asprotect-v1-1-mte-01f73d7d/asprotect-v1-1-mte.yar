import "pe"
rule ASProtect_v1_1_MTE {
  strings:
    $a0 = { 60 E9 ?? ?? ?? ?? 91 78 79 79 79 E9 }

  condition:
    $a0 at pe.entry_point
}