rule TTP_XOR_WriteProcessMemory_c720 {
  strings:
    $key_c720 = { 90 52 [2] a2 70 [2] a4 45 [2] 8a 45 [2] b5 59 }

  condition:
    any of them
}