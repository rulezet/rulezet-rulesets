rule TTP_XOR_WriteProcessMemory_ed64 {
  strings:
    $key_ed64 = { ba 16 [2] 88 34 [2] 8e 01 [2] a0 01 [2] 9f 1d }

  condition:
    any of them
}