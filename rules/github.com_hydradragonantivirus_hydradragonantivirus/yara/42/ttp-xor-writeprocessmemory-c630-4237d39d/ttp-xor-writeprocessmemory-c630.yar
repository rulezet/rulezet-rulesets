rule TTP_XOR_WriteProcessMemory_c630 {
  strings:
    $key_c630 = { 91 42 [2] a3 60 [2] a5 55 [2] 8b 55 [2] b4 49 }

  condition:
    any of them
}