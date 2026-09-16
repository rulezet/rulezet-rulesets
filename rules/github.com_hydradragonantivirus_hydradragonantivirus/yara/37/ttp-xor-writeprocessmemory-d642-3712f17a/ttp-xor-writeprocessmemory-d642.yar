rule TTP_XOR_WriteProcessMemory_d642 {
  strings:
    $key_d642 = { 81 30 [2] b3 12 [2] b5 27 [2] 9b 27 [2] a4 3b }

  condition:
    any of them
}