rule TTP_XOR_WriteProcessMemory_0b67 {
  strings:
    $key_0b67 = { 5c 15 [2] 6e 37 [2] 68 02 [2] 46 02 [2] 79 1e }

  condition:
    any of them
}