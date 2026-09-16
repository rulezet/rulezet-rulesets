rule TTP_XOR_WriteProcessMemory_d37f {
  strings:
    $key_d37f = { 84 0d [2] b6 2f [2] b0 1a [2] 9e 1a [2] a1 06 }

  condition:
    any of them
}