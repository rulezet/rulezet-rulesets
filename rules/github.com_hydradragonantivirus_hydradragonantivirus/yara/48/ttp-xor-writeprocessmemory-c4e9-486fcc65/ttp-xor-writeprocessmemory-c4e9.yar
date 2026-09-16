rule TTP_XOR_WriteProcessMemory_c4e9 {
  strings:
    $key_c4e9 = { 93 9b [2] a1 b9 [2] a7 8c [2] 89 8c [2] b6 90 }

  condition:
    any of them
}