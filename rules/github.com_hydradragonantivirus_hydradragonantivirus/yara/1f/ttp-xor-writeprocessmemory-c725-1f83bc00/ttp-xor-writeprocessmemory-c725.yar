rule TTP_XOR_WriteProcessMemory_c725 {
  strings:
    $key_c725 = { 90 57 [2] a2 75 [2] a4 40 [2] 8a 40 [2] b5 5c }

  condition:
    any of them
}