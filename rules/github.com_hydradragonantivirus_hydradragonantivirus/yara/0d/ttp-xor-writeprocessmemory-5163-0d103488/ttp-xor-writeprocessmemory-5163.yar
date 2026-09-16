rule TTP_XOR_WriteProcessMemory_5163 {
  strings:
    $key_5163 = { 06 11 [2] 34 33 [2] 32 06 [2] 1c 06 [2] 23 1a }

  condition:
    any of them
}