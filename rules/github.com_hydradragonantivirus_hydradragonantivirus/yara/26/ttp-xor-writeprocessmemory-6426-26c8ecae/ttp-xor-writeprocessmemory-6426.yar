rule TTP_XOR_WriteProcessMemory_6426 {
  strings:
    $key_6426 = { 33 54 [2] 01 76 [2] 07 43 [2] 29 43 [2] 16 5f }

  condition:
    any of them
}