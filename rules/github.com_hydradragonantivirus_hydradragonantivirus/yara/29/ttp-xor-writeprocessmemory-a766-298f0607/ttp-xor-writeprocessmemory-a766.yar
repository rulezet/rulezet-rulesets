rule TTP_XOR_WriteProcessMemory_a766 {
  strings:
    $key_a766 = { f0 14 [2] c2 36 [2] c4 03 [2] ea 03 [2] d5 1f }

  condition:
    any of them
}