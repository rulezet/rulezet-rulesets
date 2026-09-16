rule TTP_XOR_WriteProcessMemory_daa6 {
  strings:
    $key_daa6 = { 8d d4 [2] bf f6 [2] b9 c3 [2] 97 c3 [2] a8 df }

  condition:
    any of them
}