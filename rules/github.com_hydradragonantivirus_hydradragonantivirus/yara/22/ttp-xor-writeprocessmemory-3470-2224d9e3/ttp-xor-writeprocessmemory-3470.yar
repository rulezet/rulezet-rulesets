rule TTP_XOR_WriteProcessMemory_3470 {
  strings:
    $key_3470 = { 63 02 [2] 51 20 [2] 57 15 [2] 79 15 [2] 46 09 }

  condition:
    any of them
}