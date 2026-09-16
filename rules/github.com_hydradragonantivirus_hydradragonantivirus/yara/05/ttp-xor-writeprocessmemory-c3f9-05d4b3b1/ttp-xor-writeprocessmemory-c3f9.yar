rule TTP_XOR_WriteProcessMemory_c3f9 {
  strings:
    $key_c3f9 = { 94 8b [2] a6 a9 [2] a0 9c [2] 8e 9c [2] b1 80 }

  condition:
    any of them
}