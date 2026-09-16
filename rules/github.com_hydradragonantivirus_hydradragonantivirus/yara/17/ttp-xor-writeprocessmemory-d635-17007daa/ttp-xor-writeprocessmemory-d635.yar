rule TTP_XOR_WriteProcessMemory_d635 {
  strings:
    $key_d635 = { 81 47 [2] b3 65 [2] b5 50 [2] 9b 50 [2] a4 4c }

  condition:
    any of them
}