rule TTP_XOR_WriteProcessMemory_d609 {
  strings:
    $key_d609 = { 81 7b [2] b3 59 [2] b5 6c [2] 9b 6c [2] a4 70 }

  condition:
    any of them
}