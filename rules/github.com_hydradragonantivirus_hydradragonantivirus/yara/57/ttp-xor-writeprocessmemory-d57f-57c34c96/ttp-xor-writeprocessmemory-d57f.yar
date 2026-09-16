rule TTP_XOR_WriteProcessMemory_d57f {
  strings:
    $key_d57f = { 82 0d [2] b0 2f [2] b6 1a [2] 98 1a [2] a7 06 }

  condition:
    any of them
}