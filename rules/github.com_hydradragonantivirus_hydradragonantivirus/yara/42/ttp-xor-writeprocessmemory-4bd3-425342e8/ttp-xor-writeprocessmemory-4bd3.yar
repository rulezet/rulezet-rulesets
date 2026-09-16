rule TTP_XOR_WriteProcessMemory_4bd3 {
  strings:
    $key_4bd3 = { 1c a1 [2] 2e 83 [2] 28 b6 [2] 06 b6 [2] 39 aa }

  condition:
    any of them
}