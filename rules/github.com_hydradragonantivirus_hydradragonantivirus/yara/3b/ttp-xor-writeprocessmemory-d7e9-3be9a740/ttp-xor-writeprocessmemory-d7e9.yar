rule TTP_XOR_WriteProcessMemory_d7e9 {
  strings:
    $key_d7e9 = { 80 9b [2] b2 b9 [2] b4 8c [2] 9a 8c [2] a5 90 }

  condition:
    any of them
}