rule TTP_XOR_WriteProcessMemory_621f {
  strings:
    $key_621f = { 35 6d [2] 07 4f [2] 01 7a [2] 2f 7a [2] 10 66 }

  condition:
    any of them
}