rule TTP_XOR_WriteProcessMemory_3246 {
  strings:
    $key_3246 = { 65 34 [2] 57 16 [2] 51 23 [2] 7f 23 [2] 40 3f }

  condition:
    any of them
}