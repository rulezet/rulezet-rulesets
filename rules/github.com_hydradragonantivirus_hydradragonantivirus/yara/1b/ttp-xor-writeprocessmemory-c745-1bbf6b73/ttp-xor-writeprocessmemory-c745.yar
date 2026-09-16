rule TTP_XOR_WriteProcessMemory_c745 {
  strings:
    $key_c745 = { 90 37 [2] a2 15 [2] a4 20 [2] 8a 20 [2] b5 3c }

  condition:
    any of them
}