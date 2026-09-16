rule TTP_XOR_WriteProcessMemory_1e21 {
  strings:
    $key_1e21 = { 49 53 [2] 7b 71 [2] 7d 44 [2] 53 44 [2] 6c 58 }

  condition:
    any of them
}