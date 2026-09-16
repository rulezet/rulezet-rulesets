rule TTP_XOR_WriteProcessMemory_2172 {
  strings:
    $key_2172 = { 76 00 [2] 44 22 [2] 42 17 [2] 6c 17 [2] 53 0b }

  condition:
    any of them
}