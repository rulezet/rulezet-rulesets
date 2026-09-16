rule TTP_XOR_WriteProcessMemory_f90f {
  strings:
    $key_f90f = { ae 7d [2] 9c 5f [2] 9a 6a [2] b4 6a [2] 8b 76 }

  condition:
    any of them
}