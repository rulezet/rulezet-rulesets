rule TTP_XOR_WriteProcessMemory_3363 {
  strings:
    $key_3363 = { 64 11 [2] 56 33 [2] 50 06 [2] 7e 06 [2] 41 1a }

  condition:
    any of them
}