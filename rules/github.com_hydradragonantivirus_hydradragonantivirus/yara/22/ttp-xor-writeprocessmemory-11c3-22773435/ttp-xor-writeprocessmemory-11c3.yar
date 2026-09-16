rule TTP_XOR_WriteProcessMemory_11c3 {
  strings:
    $key_11c3 = { 46 b1 [2] 74 93 [2] 72 a6 [2] 5c a6 [2] 63 ba }

  condition:
    any of them
}