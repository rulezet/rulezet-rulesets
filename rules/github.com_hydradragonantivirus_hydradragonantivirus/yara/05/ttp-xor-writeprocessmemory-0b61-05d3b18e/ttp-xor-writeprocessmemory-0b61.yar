rule TTP_XOR_WriteProcessMemory_0b61 {
  strings:
    $key_0b61 = { 5c 13 [2] 6e 31 [2] 68 04 [2] 46 04 [2] 79 18 }

  condition:
    any of them
}