rule TTP_XOR_WriteProcessMemory_d442 {
  strings:
    $key_d442 = { 83 30 [2] b1 12 [2] b7 27 [2] 99 27 [2] a6 3b }

  condition:
    any of them
}