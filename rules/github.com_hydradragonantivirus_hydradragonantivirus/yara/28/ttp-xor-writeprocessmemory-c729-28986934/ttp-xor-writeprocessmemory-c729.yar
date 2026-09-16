rule TTP_XOR_WriteProcessMemory_c729 {
  strings:
    $key_c729 = { 90 5b [2] a2 79 [2] a4 4c [2] 8a 4c [2] b5 50 }

  condition:
    any of them
}