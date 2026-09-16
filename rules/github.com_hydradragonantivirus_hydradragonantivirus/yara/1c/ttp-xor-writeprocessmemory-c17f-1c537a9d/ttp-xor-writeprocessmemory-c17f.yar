rule TTP_XOR_WriteProcessMemory_c17f {
  strings:
    $key_c17f = { 96 0d [2] a4 2f [2] a2 1a [2] 8c 1a [2] b3 06 }

  condition:
    any of them
}