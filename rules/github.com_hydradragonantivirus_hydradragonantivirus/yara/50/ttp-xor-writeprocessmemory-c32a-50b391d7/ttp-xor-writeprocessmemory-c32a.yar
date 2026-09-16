rule TTP_XOR_WriteProcessMemory_c32a {
  strings:
    $key_c32a = { 94 58 [2] a6 7a [2] a0 4f [2] 8e 4f [2] b1 53 }

  condition:
    any of them
}