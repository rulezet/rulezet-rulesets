rule TTP_XOR_WriteProcessMemory_4b56 {
  strings:
    $key_4b56 = { 1c 24 [2] 2e 06 [2] 28 33 [2] 06 33 [2] 39 2f }

  condition:
    any of them
}