rule TTP_XOR_WriteProcessMemory_e426 {
  strings:
    $key_e426 = { b3 54 [2] 81 76 [2] 87 43 [2] a9 43 [2] 96 5f }

  condition:
    any of them
}