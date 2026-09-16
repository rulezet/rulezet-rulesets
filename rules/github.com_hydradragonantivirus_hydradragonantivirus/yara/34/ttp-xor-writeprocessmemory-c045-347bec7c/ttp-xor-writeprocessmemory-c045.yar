rule TTP_XOR_WriteProcessMemory_c045 {
  strings:
    $key_c045 = { 97 37 [2] a5 15 [2] a3 20 [2] 8d 20 [2] b2 3c }

  condition:
    any of them
}