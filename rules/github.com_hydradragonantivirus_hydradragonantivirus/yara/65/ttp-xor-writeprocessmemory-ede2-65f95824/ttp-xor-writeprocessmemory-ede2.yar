rule TTP_XOR_WriteProcessMemory_ede2 {
  strings:
    $key_ede2 = { ba 90 [2] 88 b2 [2] 8e 87 [2] a0 87 [2] 9f 9b }

  condition:
    any of them
}