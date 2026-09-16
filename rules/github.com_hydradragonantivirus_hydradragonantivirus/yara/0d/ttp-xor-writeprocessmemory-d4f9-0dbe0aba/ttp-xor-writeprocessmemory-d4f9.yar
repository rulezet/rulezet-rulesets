rule TTP_XOR_WriteProcessMemory_d4f9 {
  strings:
    $key_d4f9 = { 83 8b [2] b1 a9 [2] b7 9c [2] 99 9c [2] a6 80 }

  condition:
    any of them
}