rule TTP_XOR_WriteProcessMemory_11e6 {
  strings:
    $key_11e6 = { 46 94 [2] 74 b6 [2] 72 83 [2] 5c 83 [2] 63 9f }

  condition:
    any of them
}