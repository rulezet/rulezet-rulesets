rule TTP_XOR_WriteProcessMemory_3b51 {
  strings:
    $key_3b51 = { 6c 23 [2] 5e 01 [2] 58 34 [2] 76 34 [2] 49 28 }

  condition:
    any of them
}