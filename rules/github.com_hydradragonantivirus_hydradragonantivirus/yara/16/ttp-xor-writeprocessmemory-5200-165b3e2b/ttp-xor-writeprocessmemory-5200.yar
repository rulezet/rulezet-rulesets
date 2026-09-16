rule TTP_XOR_WriteProcessMemory_5200 {
  strings:
    $key_5200 = { 05 72 [2] 37 50 [2] 31 65 [2] 1f 65 [2] 20 79 }

  condition:
    any of them
}