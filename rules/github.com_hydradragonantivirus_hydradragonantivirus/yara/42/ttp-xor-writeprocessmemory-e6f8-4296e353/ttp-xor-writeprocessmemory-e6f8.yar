rule TTP_XOR_WriteProcessMemory_e6f8 {
  strings:
    $key_e6f8 = { b1 8a [2] 83 a8 [2] 85 9d [2] ab 9d [2] 94 81 }

  condition:
    any of them
}