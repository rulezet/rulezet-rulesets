rule TTP_XOR_WriteProcessMemory_c1e8 {
  strings:
    $key_c1e8 = { 96 9a [2] a4 b8 [2] a2 8d [2] 8c 8d [2] b3 91 }

  condition:
    any of them
}