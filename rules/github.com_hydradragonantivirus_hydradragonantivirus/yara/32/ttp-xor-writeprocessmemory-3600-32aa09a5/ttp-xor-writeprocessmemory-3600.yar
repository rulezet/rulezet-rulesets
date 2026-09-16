rule TTP_XOR_WriteProcessMemory_3600 {
  strings:
    $key_3600 = { 61 72 [2] 53 50 [2] 55 65 [2] 7b 65 [2] 44 79 }

  condition:
    any of them
}