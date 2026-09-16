rule TTP_XOR_WriteProcessMemory_d568 {
  strings:
    $key_d568 = { 82 1a [2] b0 38 [2] b6 0d [2] 98 0d [2] a7 11 }

  condition:
    any of them
}