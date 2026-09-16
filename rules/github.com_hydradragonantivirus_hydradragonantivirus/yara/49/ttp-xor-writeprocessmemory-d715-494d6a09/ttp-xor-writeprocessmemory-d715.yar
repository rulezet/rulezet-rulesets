rule TTP_XOR_WriteProcessMemory_d715 {
  strings:
    $key_d715 = { 80 67 [2] b2 45 [2] b4 70 [2] 9a 70 [2] a5 6c }

  condition:
    any of them
}