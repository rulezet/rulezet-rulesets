rule TTP_XOR_WriteProcessMemory_d510 {
  strings:
    $key_d510 = { 82 62 [2] b0 40 [2] b6 75 [2] 98 75 [2] a7 69 }

  condition:
    any of them
}