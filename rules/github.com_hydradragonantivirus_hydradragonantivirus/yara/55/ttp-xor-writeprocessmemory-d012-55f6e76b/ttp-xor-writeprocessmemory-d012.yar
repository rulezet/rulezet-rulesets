rule TTP_XOR_WriteProcessMemory_d012 {
  strings:
    $key_d012 = { 87 60 [2] b5 42 [2] b3 77 [2] 9d 77 [2] a2 6b }

  condition:
    any of them
}