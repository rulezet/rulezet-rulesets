rule TTP_XOR_WriteProcessMemory_d535 {
  strings:
    $key_d535 = { 82 47 [2] b0 65 [2] b6 50 [2] 98 50 [2] a7 4c }

  condition:
    any of them
}