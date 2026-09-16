rule TTP_XOR_WriteProcessMemory_2360 {
  strings:
    $key_2360 = { 74 12 [2] 46 30 [2] 40 05 [2] 6e 05 [2] 51 19 }

  condition:
    any of them
}