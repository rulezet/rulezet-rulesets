rule TTP_XOR_WriteProcessMemory_e471 {
  strings:
    $key_e471 = { b3 03 [2] 81 21 [2] 87 14 [2] a9 14 [2] 96 08 }

  condition:
    any of them
}