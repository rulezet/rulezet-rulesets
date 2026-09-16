rule TTP_XOR_WriteProcessMemory_c308 {
  strings:
    $key_c308 = { 94 7a [2] a6 58 [2] a0 6d [2] 8e 6d [2] b1 71 }

  condition:
    any of them
}