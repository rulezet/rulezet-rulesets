rule TTP_XOR_WriteProcessMemory_c702 {
  strings:
    $key_c702 = { 90 70 [2] a2 52 [2] a4 67 [2] 8a 67 [2] b5 7b }

  condition:
    any of them
}