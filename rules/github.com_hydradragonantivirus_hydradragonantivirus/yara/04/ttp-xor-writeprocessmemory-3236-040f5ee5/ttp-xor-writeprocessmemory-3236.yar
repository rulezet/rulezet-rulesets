rule TTP_XOR_WriteProcessMemory_3236 {
  strings:
    $key_3236 = { 65 44 [2] 57 66 [2] 51 53 [2] 7f 53 [2] 40 4f }

  condition:
    any of them
}