rule TTP_XOR_WriteProcessMemory_c07f {
  strings:
    $key_c07f = { 97 0d [2] a5 2f [2] a3 1a [2] 8d 1a [2] b2 06 }

  condition:
    any of them
}