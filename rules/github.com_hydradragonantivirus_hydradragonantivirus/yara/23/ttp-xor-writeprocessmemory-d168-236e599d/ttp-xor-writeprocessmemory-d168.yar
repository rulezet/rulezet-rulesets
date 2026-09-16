rule TTP_XOR_WriteProcessMemory_d168 {
  strings:
    $key_d168 = { 86 1a [2] b4 38 [2] b2 0d [2] 9c 0d [2] a3 11 }

  condition:
    any of them
}