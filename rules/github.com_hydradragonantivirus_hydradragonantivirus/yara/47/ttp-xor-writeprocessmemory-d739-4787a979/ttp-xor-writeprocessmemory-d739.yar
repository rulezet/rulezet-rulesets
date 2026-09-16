rule TTP_XOR_WriteProcessMemory_d739 {
  strings:
    $key_d739 = { 80 4b [2] b2 69 [2] b4 5c [2] 9a 5c [2] a5 40 }

  condition:
    any of them
}