rule TTP_XOR_WriteProcessMemory_d64a {
  strings:
    $key_d64a = { 81 38 [2] b3 1a [2] b5 2f [2] 9b 2f [2] a4 33 }

  condition:
    any of them
}