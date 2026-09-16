rule TTP_XOR_WriteProcessMemory_c0e8 {
  strings:
    $key_c0e8 = { 97 9a [2] a5 b8 [2] a3 8d [2] 8d 8d [2] b2 91 }

  condition:
    any of them
}