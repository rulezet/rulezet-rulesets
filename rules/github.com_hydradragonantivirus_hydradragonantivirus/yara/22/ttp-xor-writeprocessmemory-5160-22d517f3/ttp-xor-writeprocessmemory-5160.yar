rule TTP_XOR_WriteProcessMemory_5160 {
  strings:
    $key_5160 = { 06 12 [2] 34 30 [2] 32 05 [2] 1c 05 [2] 23 19 }

  condition:
    any of them
}