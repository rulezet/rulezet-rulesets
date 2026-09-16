rule TTP_XOR_WriteProcessMemory_5b43 {
  strings:
    $key_5b43 = { 0c 31 [2] 3e 13 [2] 38 26 [2] 16 26 [2] 29 3a }

  condition:
    any of them
}