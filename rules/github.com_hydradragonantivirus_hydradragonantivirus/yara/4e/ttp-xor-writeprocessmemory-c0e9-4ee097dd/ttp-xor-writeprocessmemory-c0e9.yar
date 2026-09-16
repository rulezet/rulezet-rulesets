rule TTP_XOR_WriteProcessMemory_c0e9 {
  strings:
    $key_c0e9 = { 97 9b [2] a5 b9 [2] a3 8c [2] 8d 8c [2] b2 90 }

  condition:
    any of them
}