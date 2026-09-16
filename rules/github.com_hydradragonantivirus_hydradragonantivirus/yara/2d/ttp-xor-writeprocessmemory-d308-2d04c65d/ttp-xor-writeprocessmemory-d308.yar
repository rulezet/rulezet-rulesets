rule TTP_XOR_WriteProcessMemory_d308 {
  strings:
    $key_d308 = { 84 7a [2] b6 58 [2] b0 6d [2] 9e 6d [2] a1 71 }

  condition:
    any of them
}