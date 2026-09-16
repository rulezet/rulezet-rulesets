rule TTP_XOR_WriteProcessMemory_c55a {
  strings:
    $key_c55a = { 92 28 [2] a0 0a [2] a6 3f [2] 88 3f [2] b7 23 }

  condition:
    any of them
}