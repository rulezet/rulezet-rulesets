rule TTP_XOR_WriteProcessMemory_c75a {
  strings:
    $key_c75a = { 90 28 [2] a2 0a [2] a4 3f [2] 8a 3f [2] b5 23 }

  condition:
    any of them
}