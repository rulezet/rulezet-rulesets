rule TTP_XOR_WriteProcessMemory_7771 {
  strings:
    $key_7771 = { 20 03 [2] 12 21 [2] 14 14 [2] 3a 14 [2] 05 08 }

  condition:
    any of them
}