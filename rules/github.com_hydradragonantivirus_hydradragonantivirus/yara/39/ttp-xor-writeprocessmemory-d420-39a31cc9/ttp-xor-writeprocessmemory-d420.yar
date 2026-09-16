rule TTP_XOR_WriteProcessMemory_d420 {
  strings:
    $key_d420 = { 83 52 [2] b1 70 [2] b7 45 [2] 99 45 [2] a6 59 }

  condition:
    any of them
}