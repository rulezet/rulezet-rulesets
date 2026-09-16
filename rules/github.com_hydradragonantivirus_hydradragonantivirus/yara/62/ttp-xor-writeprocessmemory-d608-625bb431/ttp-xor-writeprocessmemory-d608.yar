rule TTP_XOR_WriteProcessMemory_d608 {
  strings:
    $key_d608 = { 81 7a [2] b3 58 [2] b5 6d [2] 9b 6d [2] a4 71 }

  condition:
    any of them
}