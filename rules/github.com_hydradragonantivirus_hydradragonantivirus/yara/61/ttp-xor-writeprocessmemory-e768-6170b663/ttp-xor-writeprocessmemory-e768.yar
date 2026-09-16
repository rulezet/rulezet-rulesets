rule TTP_XOR_WriteProcessMemory_e768 {
  strings:
    $key_e768 = { b0 1a [2] 82 38 [2] 84 0d [2] aa 0d [2] 95 11 }

  condition:
    any of them
}