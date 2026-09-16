rule TTP_XOR_WriteProcessMemory_c468 {
  strings:
    $key_c468 = { 93 1a [2] a1 38 [2] a7 0d [2] 89 0d [2] b6 11 }

  condition:
    any of them
}