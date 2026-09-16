rule TTP_XOR_WriteProcessMemory_d009 {
  strings:
    $key_d009 = { 87 7b [2] b5 59 [2] b3 6c [2] 9d 6c [2] a2 70 }

  condition:
    any of them
}