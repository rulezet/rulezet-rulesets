rule TTP_XOR_WriteProcessMemory_c35a {
  strings:
    $key_c35a = { 94 28 [2] a6 0a [2] a0 3f [2] 8e 3f [2] b1 23 }

  condition:
    any of them
}