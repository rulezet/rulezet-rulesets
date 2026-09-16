rule TTP_XOR_WriteProcessMemory_1e51 {
  strings:
    $key_1e51 = { 49 23 [2] 7b 01 [2] 7d 34 [2] 53 34 [2] 6c 28 }

  condition:
    any of them
}