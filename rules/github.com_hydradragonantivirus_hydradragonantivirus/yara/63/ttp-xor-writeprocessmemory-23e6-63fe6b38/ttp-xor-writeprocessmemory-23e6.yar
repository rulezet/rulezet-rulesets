rule TTP_XOR_WriteProcessMemory_23e6 {
  strings:
    $key_23e6 = { 74 94 [2] 46 b6 [2] 40 83 [2] 6e 83 [2] 51 9f }

  condition:
    any of them
}