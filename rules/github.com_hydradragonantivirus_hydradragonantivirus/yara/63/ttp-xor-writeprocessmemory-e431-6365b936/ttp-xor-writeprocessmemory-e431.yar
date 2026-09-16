rule TTP_XOR_WriteProcessMemory_e431 {
  strings:
    $key_e431 = { b3 43 [2] 81 61 [2] 87 54 [2] a9 54 [2] 96 48 }

  condition:
    any of them
}