rule TTP_XOR_WriteProcessMemory_d115 {
  strings:
    $key_d115 = { 86 67 [2] b4 45 [2] b2 70 [2] 9c 70 [2] a3 6c }

  condition:
    any of them
}