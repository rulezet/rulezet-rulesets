rule TTP_XOR_WriteProcessMemory_d662 {
  strings:
    $key_d662 = { 81 10 [2] b3 32 [2] b5 07 [2] 9b 07 [2] a4 1b }

  condition:
    any of them
}