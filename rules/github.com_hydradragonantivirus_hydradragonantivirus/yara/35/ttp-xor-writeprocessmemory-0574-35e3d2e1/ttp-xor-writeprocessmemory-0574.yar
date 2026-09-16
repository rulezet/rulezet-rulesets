rule TTP_XOR_WriteProcessMemory_0574 {
  strings:
    $key_0574 = { 52 06 [2] 60 24 [2] 66 11 [2] 48 11 [2] 77 0d }

  condition:
    any of them
}