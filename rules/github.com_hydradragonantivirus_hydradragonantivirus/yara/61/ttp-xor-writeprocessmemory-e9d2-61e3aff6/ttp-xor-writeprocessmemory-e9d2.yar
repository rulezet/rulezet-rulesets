rule TTP_XOR_WriteProcessMemory_e9d2 {
  strings:
    $key_e9d2 = { be a0 [2] 8c 82 [2] 8a b7 [2] a4 b7 [2] 9b ab }

  condition:
    any of them
}