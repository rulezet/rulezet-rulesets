rule TTP_XOR_WriteProcessMemory_d60f {
  strings:
    $key_d60f = { 81 7d [2] b3 5f [2] b5 6a [2] 9b 6a [2] a4 76 }

  condition:
    any of them
}