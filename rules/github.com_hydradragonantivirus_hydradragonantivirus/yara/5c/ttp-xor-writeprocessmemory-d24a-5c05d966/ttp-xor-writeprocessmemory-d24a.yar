rule TTP_XOR_WriteProcessMemory_d24a {
  strings:
    $key_d24a = { 85 38 [2] b7 1a [2] b1 2f [2] 9f 2f [2] a0 33 }

  condition:
    any of them
}