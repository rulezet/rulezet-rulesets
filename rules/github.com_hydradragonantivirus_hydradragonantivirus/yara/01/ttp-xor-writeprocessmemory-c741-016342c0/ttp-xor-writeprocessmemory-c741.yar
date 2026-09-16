rule TTP_XOR_WriteProcessMemory_c741 {
  strings:
    $key_c741 = { 90 33 [2] a2 11 [2] a4 24 [2] 8a 24 [2] b5 38 }

  condition:
    any of them
}