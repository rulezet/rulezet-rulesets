rule TTP_XOR_WriteProcessMemory_c429 {
  strings:
    $key_c429 = { 93 5b [2] a1 79 [2] a7 4c [2] 89 4c [2] b6 50 }

  condition:
    any of them
}