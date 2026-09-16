rule TTP_XOR_WriteProcessMemory_d733 {
  strings:
    $key_d733 = { 80 41 [2] b2 63 [2] b4 56 [2] 9a 56 [2] a5 4a }

  condition:
    any of them
}