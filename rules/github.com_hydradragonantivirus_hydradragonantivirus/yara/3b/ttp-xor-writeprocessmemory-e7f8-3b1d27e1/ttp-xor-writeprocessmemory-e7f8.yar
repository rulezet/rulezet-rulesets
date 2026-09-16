rule TTP_XOR_WriteProcessMemory_e7f8 {
  strings:
    $key_e7f8 = { b0 8a [2] 82 a8 [2] 84 9d [2] aa 9d [2] 95 81 }

  condition:
    any of them
}