rule TTP_XOR_WriteProcessMemory_edf7 {
  strings:
    $key_edf7 = { ba 85 [2] 88 a7 [2] 8e 92 [2] a0 92 [2] 9f 8e }

  condition:
    any of them
}