rule TTP_XOR_WriteProcessMemory_ede6 {
  strings:
    $key_ede6 = { ba 94 [2] 88 b6 [2] 8e 83 [2] a0 83 [2] 9f 9f }

  condition:
    any of them
}