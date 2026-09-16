rule TTP_XOR_WriteProcessMemory_c159 {
  strings:
    $key_c159 = { 96 2b [2] a4 09 [2] a2 3c [2] 8c 3c [2] b3 20 }

  condition:
    any of them
}