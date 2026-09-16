rule TTP_XOR_WriteProcessMemory_c6e8 {
  strings:
    $key_c6e8 = { 91 9a [2] a3 b8 [2] a5 8d [2] 8b 8d [2] b4 91 }

  condition:
    any of them
}