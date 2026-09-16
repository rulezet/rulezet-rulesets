rule TTP_XOR_WriteProcessMemory_c5e8 {
  strings:
    $key_c5e8 = { 92 9a [2] a0 b8 [2] a6 8d [2] 88 8d [2] b7 91 }

  condition:
    any of them
}