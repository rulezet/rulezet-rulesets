rule TTP_XOR_WriteProcessMemory_2d7f {
  strings:
    $key_2d7f = { 7a 0d [2] 48 2f [2] 4e 1a [2] 60 1a [2] 5f 06 }

  condition:
    any of them
}