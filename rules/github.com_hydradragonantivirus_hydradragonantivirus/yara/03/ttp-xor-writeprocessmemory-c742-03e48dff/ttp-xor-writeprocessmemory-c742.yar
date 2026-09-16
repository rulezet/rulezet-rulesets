rule TTP_XOR_WriteProcessMemory_c742 {
  strings:
    $key_c742 = { 90 30 [2] a2 12 [2] a4 27 [2] 8a 27 [2] b5 3b }

  condition:
    any of them
}