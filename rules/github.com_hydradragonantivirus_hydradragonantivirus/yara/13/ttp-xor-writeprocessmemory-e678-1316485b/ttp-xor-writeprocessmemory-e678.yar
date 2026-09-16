rule TTP_XOR_WriteProcessMemory_e678 {
  strings:
    $key_e678 = { b1 0a [2] 83 28 [2] 85 1d [2] ab 1d [2] 94 01 }

  condition:
    any of them
}