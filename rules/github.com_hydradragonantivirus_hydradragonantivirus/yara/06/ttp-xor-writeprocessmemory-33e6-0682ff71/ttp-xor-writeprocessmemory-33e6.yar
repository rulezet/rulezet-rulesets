rule TTP_XOR_WriteProcessMemory_33e6 {
  strings:
    $key_33e6 = { 64 94 [2] 56 b6 [2] 50 83 [2] 7e 83 [2] 41 9f }

  condition:
    any of them
}