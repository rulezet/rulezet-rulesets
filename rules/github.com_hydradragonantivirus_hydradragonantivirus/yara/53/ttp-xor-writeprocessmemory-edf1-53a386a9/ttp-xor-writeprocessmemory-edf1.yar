rule TTP_XOR_WriteProcessMemory_edf1 {
  strings:
    $key_edf1 = { ba 83 [2] 88 a1 [2] 8e 94 [2] a0 94 [2] 9f 88 }

  condition:
    any of them
}