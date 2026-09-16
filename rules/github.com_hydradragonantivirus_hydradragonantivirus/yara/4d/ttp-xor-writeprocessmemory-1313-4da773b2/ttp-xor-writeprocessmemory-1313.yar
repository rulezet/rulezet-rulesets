rule TTP_XOR_WriteProcessMemory_1313 {
  strings:
    $key_1313 = { 44 61 [2] 76 43 [2] 70 76 [2] 5e 76 [2] 61 6a }

  condition:
    any of them
}