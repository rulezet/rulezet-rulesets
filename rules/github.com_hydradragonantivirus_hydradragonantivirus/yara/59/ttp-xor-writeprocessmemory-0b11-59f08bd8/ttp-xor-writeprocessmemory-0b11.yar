rule TTP_XOR_WriteProcessMemory_0b11 {
  strings:
    $key_0b11 = { 5c 63 [2] 6e 41 [2] 68 74 [2] 46 74 [2] 79 68 }

  condition:
    any of them
}