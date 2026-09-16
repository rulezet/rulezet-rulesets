rule PEiD_00644_EXEPACK__LINK__v3_60__v3_64__v3_65_or_5_01_21_ {
  meta:
    description = "[EXEPACK (LINK) v3.60, v3.64, v3.65 or 5.01.21]"
    ep_only     = "true"

  strings:
    $a = { 8C C0 05 ?? ?? 0E 1F A3 ?? ?? 03 ?? ?? ?? 8E C0 8B ?? ?? ?? 8B ?? 4F 8B F7 FD F3 A4 50 B8 ?? ?? 50 CB }

  condition:
    $a
}