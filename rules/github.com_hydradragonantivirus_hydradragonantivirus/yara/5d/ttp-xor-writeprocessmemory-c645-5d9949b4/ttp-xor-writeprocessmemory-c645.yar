rule TTP_XOR_WriteProcessMemory_c645 {
  strings:
    $key_c645 = { 91 37 [2] a3 15 [2] a5 20 [2] 8b 20 [2] b4 3c }

  condition:
    any of them
}