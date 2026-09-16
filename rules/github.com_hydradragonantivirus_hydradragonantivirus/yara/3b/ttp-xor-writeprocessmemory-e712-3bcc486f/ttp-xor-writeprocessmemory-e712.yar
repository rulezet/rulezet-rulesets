rule TTP_XOR_WriteProcessMemory_e712 {
  strings:
    $key_e712 = { b0 60 [2] 82 42 [2] 84 77 [2] aa 77 [2] 95 6b }

  condition:
    any of them
}