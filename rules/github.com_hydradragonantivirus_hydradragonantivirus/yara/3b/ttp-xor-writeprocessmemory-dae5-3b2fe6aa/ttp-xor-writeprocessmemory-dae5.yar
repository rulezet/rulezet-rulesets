rule TTP_XOR_WriteProcessMemory_dae5 {
  strings:
    $key_dae5 = { 8d 97 [2] bf b5 [2] b9 80 [2] 97 80 [2] a8 9c }

  condition:
    any of them
}