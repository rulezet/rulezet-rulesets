rule TTP_XOR_WriteProcessMemory_d108 {
  strings:
    $key_d108 = { 86 7a [2] b4 58 [2] b2 6d [2] 9c 6d [2] a3 71 }

  condition:
    any of them
}