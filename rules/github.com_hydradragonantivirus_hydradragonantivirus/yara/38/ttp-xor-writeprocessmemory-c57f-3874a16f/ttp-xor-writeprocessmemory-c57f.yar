rule TTP_XOR_WriteProcessMemory_c57f {
  strings:
    $key_c57f = { 92 0d [2] a0 2f [2] a6 1a [2] 88 1a [2] b7 06 }

  condition:
    any of them
}