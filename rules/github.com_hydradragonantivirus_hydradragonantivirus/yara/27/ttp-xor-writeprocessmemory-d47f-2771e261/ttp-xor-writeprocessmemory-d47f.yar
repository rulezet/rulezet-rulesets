rule TTP_XOR_WriteProcessMemory_d47f {
  strings:
    $key_d47f = { 83 0d [2] b1 2f [2] b7 1a [2] 99 1a [2] a6 06 }

  condition:
    any of them
}