rule TTP_XOR_WriteProcessMemory_0b60 {
  strings:
    $key_0b60 = { 5c 12 [2] 6e 30 [2] 68 05 [2] 46 05 [2] 79 19 }

  condition:
    any of them
}