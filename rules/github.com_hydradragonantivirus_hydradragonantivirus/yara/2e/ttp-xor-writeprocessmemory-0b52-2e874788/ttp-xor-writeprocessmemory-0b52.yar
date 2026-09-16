rule TTP_XOR_WriteProcessMemory_0b52 {
  strings:
    $key_0b52 = { 5c 20 [2] 6e 02 [2] 68 37 [2] 46 37 [2] 79 2b }

  condition:
    any of them
}