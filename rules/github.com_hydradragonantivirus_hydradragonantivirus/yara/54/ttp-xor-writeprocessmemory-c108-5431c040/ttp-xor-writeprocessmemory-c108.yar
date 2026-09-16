rule TTP_XOR_WriteProcessMemory_c108 {
  strings:
    $key_c108 = { 96 7a [2] a4 58 [2] a2 6d [2] 8c 6d [2] b3 71 }

  condition:
    any of them
}