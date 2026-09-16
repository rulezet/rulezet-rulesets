rule TTP_XOR_WriteProcessMemory_6d1f {
  strings:
    $key_6d1f = { 3a 6d [2] 08 4f [2] 0e 7a [2] 20 7a [2] 1f 66 }

  condition:
    any of them
}