rule TTP_XOR_WriteProcessMemory_d4e8 {
  strings:
    $key_d4e8 = { 83 9a [2] b1 b8 [2] b7 8d [2] 99 8d [2] a6 91 }

  condition:
    any of them
}