rule TTP_XOR_WriteProcessMemory_c57a {
  strings:
    $key_c57a = { 92 08 [2] a0 2a [2] a6 1f [2] 88 1f [2] b7 03 }

  condition:
    any of them
}