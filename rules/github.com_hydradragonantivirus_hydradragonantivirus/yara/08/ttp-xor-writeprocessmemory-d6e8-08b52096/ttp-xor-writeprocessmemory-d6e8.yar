rule TTP_XOR_WriteProcessMemory_d6e8 {
  strings:
    $key_d6e8 = { 81 9a [2] b3 b8 [2] b5 8d [2] 9b 8d [2] a4 91 }

  condition:
    any of them
}