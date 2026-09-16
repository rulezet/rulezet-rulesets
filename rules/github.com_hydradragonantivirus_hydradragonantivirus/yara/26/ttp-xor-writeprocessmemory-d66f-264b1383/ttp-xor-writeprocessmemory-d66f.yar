rule TTP_XOR_WriteProcessMemory_d66f {
  strings:
    $key_d66f = { 81 1d [2] b3 3f [2] b5 0a [2] 9b 0a [2] a4 16 }

  condition:
    any of them
}