rule TTP_XOR_WriteProcessMemory_d242 {
  strings:
    $key_d242 = { 85 30 [2] b7 12 [2] b1 27 [2] 9f 27 [2] a0 3b }

  condition:
    any of them
}