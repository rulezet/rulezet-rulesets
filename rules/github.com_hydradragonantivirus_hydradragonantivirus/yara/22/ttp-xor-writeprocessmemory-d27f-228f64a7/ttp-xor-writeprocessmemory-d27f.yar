rule TTP_XOR_WriteProcessMemory_d27f {
  strings:
    $key_d27f = { 85 0d [2] b7 2f [2] b1 1a [2] 9f 1a [2] a0 06 }

  condition:
    any of them
}