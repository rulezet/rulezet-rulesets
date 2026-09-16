rule TTP_XOR_WriteProcessMemory_d65a {
  strings:
    $key_d65a = { 81 28 [2] b3 0a [2] b5 3f [2] 9b 3f [2] a4 23 }

  condition:
    any of them
}