rule TTP_XOR_WriteProcessMemory_e668 {
  strings:
    $key_e668 = { b1 1a [2] 83 38 [2] 85 0d [2] ab 0d [2] 94 11 }

  condition:
    any of them
}