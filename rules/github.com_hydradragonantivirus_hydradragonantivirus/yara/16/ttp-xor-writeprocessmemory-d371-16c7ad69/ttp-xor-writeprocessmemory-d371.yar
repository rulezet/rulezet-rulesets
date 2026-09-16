rule TTP_XOR_WriteProcessMemory_d371 {
  strings:
    $key_d371 = { 84 03 [2] b6 21 [2] b0 14 [2] 9e 14 [2] a1 08 }

  condition:
    any of them
}