rule TTP_XOR_WriteProcessMemory_c768 {
  strings:
    $key_c768 = { 90 1a [2] a2 38 [2] a4 0d [2] 8a 0d [2] b5 11 }

  condition:
    any of them
}