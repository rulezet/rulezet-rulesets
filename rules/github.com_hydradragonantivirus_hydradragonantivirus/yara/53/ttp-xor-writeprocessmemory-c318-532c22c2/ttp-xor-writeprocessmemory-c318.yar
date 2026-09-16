rule TTP_XOR_WriteProcessMemory_c318 {
  strings:
    $key_c318 = { 94 6a [2] a6 48 [2] a0 7d [2] 8e 7d [2] b1 61 }

  condition:
    any of them
}