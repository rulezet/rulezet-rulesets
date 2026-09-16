rule TTP_XOR_WriteProcessMemory_c374 {
  strings:
    $key_c374 = { 94 06 [2] a6 24 [2] a0 11 [2] 8e 11 [2] b1 0d }

  condition:
    any of them
}