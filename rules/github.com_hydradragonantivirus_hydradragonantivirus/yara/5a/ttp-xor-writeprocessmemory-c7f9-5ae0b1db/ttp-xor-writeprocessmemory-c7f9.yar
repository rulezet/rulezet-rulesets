rule TTP_XOR_WriteProcessMemory_c7f9 {
  strings:
    $key_c7f9 = { 90 8b [2] a2 a9 [2] a4 9c [2] 8a 9c [2] b5 80 }

  condition:
    any of them
}