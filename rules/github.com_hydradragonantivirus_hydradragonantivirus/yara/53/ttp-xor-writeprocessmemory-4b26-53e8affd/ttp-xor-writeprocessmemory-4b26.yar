rule TTP_XOR_WriteProcessMemory_4b26 {
  strings:
    $key_4b26 = { 1c 54 [2] 2e 76 [2] 28 43 [2] 06 43 [2] 39 5f }

  condition:
    any of them
}