rule TTP_XOR_WriteProcessMemory_e608 {
  strings:
    $key_e608 = { b1 7a [2] 83 58 [2] 85 6d [2] ab 6d [2] 94 71 }

  condition:
    any of them
}