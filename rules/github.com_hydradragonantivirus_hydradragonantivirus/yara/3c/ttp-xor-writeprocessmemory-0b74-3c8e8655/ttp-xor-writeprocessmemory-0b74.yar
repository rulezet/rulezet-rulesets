rule TTP_XOR_WriteProcessMemory_0b74 {
  strings:
    $key_0b74 = { 5c 06 [2] 6e 24 [2] 68 11 [2] 46 11 [2] 79 0d }

  condition:
    any of them
}