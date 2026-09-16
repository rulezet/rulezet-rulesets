rule TTP_XOR_WriteProcessMemory_7160 {
  strings:
    $key_7160 = { 26 12 [2] 14 30 [2] 12 05 [2] 3c 05 [2] 03 19 }

  condition:
    any of them
}