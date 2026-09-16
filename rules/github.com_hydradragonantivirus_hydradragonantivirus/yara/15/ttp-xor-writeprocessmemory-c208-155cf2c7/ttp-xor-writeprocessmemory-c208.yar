rule TTP_XOR_WriteProcessMemory_c208 {
  strings:
    $key_c208 = { 95 7a [2] a7 58 [2] a1 6d [2] 8f 6d [2] b0 71 }

  condition:
    any of them
}