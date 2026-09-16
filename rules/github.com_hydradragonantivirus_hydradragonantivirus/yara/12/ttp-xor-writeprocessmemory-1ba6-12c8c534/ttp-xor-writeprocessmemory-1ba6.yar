rule TTP_XOR_WriteProcessMemory_1ba6 {
  strings:
    $key_1ba6 = { 4c d4 [2] 7e f6 [2] 78 c3 [2] 56 c3 [2] 69 df }

  condition:
    any of them
}