rule TTP_XOR_WriteProcessMemory_c668 {
  strings:
    $key_c668 = { 91 1a [2] a3 38 [2] a5 0d [2] 8b 0d [2] b4 11 }

  condition:
    any of them
}