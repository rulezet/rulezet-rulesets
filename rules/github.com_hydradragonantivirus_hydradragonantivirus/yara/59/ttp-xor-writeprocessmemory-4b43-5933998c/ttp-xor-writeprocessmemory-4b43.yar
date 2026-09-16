rule TTP_XOR_WriteProcessMemory_4b43 {
  strings:
    $key_4b43 = { 1c 31 [2] 2e 13 [2] 28 26 [2] 06 26 [2] 39 3a }

  condition:
    any of them
}