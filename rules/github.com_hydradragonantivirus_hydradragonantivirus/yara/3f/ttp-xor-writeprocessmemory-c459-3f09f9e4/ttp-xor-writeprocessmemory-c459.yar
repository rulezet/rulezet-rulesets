rule TTP_XOR_WriteProcessMemory_c459 {
  strings:
    $key_c459 = { 93 2b [2] a1 09 [2] a7 3c [2] 89 3c [2] b6 20 }

  condition:
    any of them
}