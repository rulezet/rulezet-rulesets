rule TTP_XOR_WriteProcessMemory_1e11 {
  strings:
    $key_1e11 = { 49 63 [2] 7b 41 [2] 7d 74 [2] 53 74 [2] 6c 68 }

  condition:
    any of them
}