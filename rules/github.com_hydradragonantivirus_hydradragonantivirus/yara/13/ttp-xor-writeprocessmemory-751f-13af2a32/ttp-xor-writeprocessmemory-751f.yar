rule TTP_XOR_WriteProcessMemory_751f {
  strings:
    $key_751f = { 22 6d [2] 10 4f [2] 16 7a [2] 38 7a [2] 07 66 }

  condition:
    any of them
}