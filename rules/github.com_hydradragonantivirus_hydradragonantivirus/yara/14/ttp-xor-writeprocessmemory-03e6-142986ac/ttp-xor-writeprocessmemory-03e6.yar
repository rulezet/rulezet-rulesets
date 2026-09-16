rule TTP_XOR_WriteProcessMemory_03e6 {
  strings:
    $key_03e6 = { 54 94 [2] 66 b6 [2] 60 83 [2] 4e 83 [2] 71 9f }

  condition:
    any of them
}