rule TTP_XOR_WriteProcessMemory_c012 {
  strings:
    $key_c012 = { 97 60 [2] a5 42 [2] a3 77 [2] 8d 77 [2] b2 6b }

  condition:
    any of them
}