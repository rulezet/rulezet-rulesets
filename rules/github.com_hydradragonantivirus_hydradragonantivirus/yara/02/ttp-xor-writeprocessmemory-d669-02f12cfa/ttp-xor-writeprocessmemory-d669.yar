rule TTP_XOR_WriteProcessMemory_d669 {
  strings:
    $key_d669 = { 81 1b [2] b3 39 [2] b5 0c [2] 9b 0c [2] a4 10 }

  condition:
    any of them
}