rule TTP_XOR_WriteProcessMemory_d274 {
  strings:
    $key_d274 = { 85 06 [2] b7 24 [2] b1 11 [2] 9f 11 [2] a0 0d }

  condition:
    any of them
}