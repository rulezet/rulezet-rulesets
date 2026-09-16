rule TTP_XOR_WriteProcessMemory_14e6 {
  strings:
    $key_14e6 = { 43 94 [2] 71 b6 [2] 77 83 [2] 59 83 [2] 66 9f }

  condition:
    any of them
}