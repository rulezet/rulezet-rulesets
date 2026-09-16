rule TTP_XOR_WriteProcessMemory_3b02 {
  strings:
    $key_3b02 = { 6c 70 [2] 5e 52 [2] 58 67 [2] 76 67 [2] 49 7b }

  condition:
    any of them
}