rule TTP_XOR_WriteProcessMemory_daa5 {
  strings:
    $key_daa5 = { 8d d7 [2] bf f5 [2] b9 c0 [2] 97 c0 [2] a8 dc }

  condition:
    any of them
}