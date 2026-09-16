rule TTP_XOR_WriteProcessMemory_d67f {
  strings:
    $key_d67f = { 81 0d [2] b3 2f [2] b5 1a [2] 9b 1a [2] a4 06 }

  condition:
    any of them
}