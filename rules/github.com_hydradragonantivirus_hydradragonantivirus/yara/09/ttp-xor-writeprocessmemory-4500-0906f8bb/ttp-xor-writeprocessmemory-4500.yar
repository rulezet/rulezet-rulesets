rule TTP_XOR_WriteProcessMemory_4500 {
  strings:
    $key_4500 = { 12 72 [2] 20 50 [2] 26 65 [2] 08 65 [2] 37 79 }

  condition:
    any of them
}