rule TTP_XOR_WriteProcessMemory_d320 {
  strings:
    $key_d320 = { 84 52 [2] b6 70 [2] b0 45 [2] 9e 45 [2] a1 59 }

  condition:
    any of them
}