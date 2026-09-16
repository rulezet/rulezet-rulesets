rule TTP_XOR_WriteProcessMemory_d412 {
  strings:
    $key_d412 = { 83 60 [2] b1 42 [2] b7 77 [2] 99 77 [2] a6 6b }

  condition:
    any of them
}