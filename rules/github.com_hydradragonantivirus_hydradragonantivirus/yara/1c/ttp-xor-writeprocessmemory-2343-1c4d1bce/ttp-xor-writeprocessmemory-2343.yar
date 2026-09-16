rule TTP_XOR_WriteProcessMemory_2343 {
  strings:
    $key_2343 = { 74 31 [2] 46 13 [2] 40 26 [2] 6e 26 [2] 51 3a }

  condition:
    any of them
}