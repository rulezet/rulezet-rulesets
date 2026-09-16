rule TTP_XOR_WriteProcessMemory_d271 {
  strings:
    $key_d271 = { 85 03 [2] b7 21 [2] b1 14 [2] 9f 14 [2] a0 08 }

  condition:
    any of them
}