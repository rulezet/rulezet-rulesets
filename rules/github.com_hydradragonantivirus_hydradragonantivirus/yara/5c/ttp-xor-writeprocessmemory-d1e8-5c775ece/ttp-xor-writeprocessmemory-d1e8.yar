rule TTP_XOR_WriteProcessMemory_d1e8 {
  strings:
    $key_d1e8 = { 86 9a [2] b4 b8 [2] b2 8d [2] 9c 8d [2] a3 91 }

  condition:
    any of them
}