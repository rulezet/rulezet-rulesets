rule TTP_XOR_WriteProcessMemory_d6e9 {
  strings:
    $key_d6e9 = { 81 9b [2] b3 b9 [2] b5 8c [2] 9b 8c [2] a4 90 }

  condition:
    any of them
}