rule TTP_XOR_WriteProcessMemory_2370 {
  strings:
    $key_2370 = { 74 02 [2] 46 20 [2] 40 15 [2] 6e 15 [2] 51 09 }

  condition:
    any of them
}