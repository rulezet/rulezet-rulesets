rule TTP_XOR_WriteProcessMemory_c0f8 {
  strings:
    $key_c0f8 = { 97 8a [2] a5 a8 [2] a3 9d [2] 8d 9d [2] b2 81 }

  condition:
    any of them
}