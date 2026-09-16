rule TTP_XOR_WriteProcessMemory_0b54 {
  strings:
    $key_0b54 = { 5c 26 [2] 6e 04 [2] 68 31 [2] 46 31 [2] 79 2d }

  condition:
    any of them
}