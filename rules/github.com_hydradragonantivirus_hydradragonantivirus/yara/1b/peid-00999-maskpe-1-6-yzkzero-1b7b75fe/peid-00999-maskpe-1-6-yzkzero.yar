rule PEiD_00999_MaskPE_1_6____yzkzero_ {
  meta:
    description = "[MaskPE 1.6 -> yzkzero]"
    ep_only     = "false"

  strings:
    $a = { 36 81 2C 24 ?? ?? ?? 00 C3 60 }

  condition:
    $a
}