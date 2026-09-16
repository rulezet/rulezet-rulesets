rule TTP_XOR_WriteProcessMemory_d8f8 {
  strings:
    $key_d8f8 = { 8f 8a [2] bd a8 [2] bb 9d [2] 95 9d [2] aa 81 }

  condition:
    any of them
}