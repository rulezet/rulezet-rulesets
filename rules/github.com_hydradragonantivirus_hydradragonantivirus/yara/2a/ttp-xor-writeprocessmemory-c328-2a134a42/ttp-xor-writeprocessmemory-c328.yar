rule TTP_XOR_WriteProcessMemory_c328 {
  strings:
    $key_c328 = { 94 5a [2] a6 78 [2] a0 4d [2] 8e 4d [2] b1 51 }

  condition:
    any of them
}