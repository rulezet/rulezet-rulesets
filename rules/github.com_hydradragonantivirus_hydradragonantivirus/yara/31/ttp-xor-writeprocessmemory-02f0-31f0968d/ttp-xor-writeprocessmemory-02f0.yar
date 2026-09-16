rule TTP_XOR_WriteProcessMemory_02f0 {
  strings:
    $key_02f0 = { 55 82 [2] 67 a0 [2] 61 95 [2] 4f 95 [2] 70 89 }

  condition:
    any of them
}