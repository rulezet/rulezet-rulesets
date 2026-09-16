rule TTP_XOR_WriteProcessMemory_c5e9 {
  strings:
    $key_c5e9 = { 92 9b [2] a0 b9 [2] a6 8c [2] 88 8c [2] b7 90 }

  condition:
    any of them
}