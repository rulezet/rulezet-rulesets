rule TTP_XOR_WriteProcessMemory_c3e9 {
  strings:
    $key_c3e9 = { 94 9b [2] a6 b9 [2] a0 8c [2] 8e 8c [2] b1 90 }

  condition:
    any of them
}