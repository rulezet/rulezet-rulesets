rule TTP_XOR_WriteProcessMemory_d435 {
  strings:
    $key_d435 = { 83 47 [2] b1 65 [2] b7 50 [2] 99 50 [2] a6 4c }

  condition:
    any of them
}