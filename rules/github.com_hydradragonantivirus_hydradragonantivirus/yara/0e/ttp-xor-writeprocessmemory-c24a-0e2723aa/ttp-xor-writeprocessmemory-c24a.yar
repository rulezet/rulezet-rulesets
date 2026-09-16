rule TTP_XOR_WriteProcessMemory_c24a {
  strings:
    $key_c24a = { 95 38 [2] a7 1a [2] a1 2f [2] 8f 2f [2] b0 33 }

  condition:
    any of them
}