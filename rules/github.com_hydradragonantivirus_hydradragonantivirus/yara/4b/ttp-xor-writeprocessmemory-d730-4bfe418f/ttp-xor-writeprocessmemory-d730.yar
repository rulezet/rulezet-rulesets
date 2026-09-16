rule TTP_XOR_WriteProcessMemory_d730 {
  strings:
    $key_d730 = { 80 42 [2] b2 60 [2] b4 55 [2] 9a 55 [2] a5 49 }

  condition:
    any of them
}