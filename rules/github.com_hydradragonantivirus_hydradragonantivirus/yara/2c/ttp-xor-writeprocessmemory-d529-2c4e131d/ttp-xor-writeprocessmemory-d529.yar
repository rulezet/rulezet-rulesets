rule TTP_XOR_WriteProcessMemory_d529 {
  strings:
    $key_d529 = { 82 5b [2] b0 79 [2] b6 4c [2] 98 4c [2] a7 50 }

  condition:
    any of them
}