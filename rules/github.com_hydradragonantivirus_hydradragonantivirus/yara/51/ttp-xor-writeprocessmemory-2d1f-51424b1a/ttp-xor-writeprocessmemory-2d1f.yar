rule TTP_XOR_WriteProcessMemory_2d1f {
  strings:
    $key_2d1f = { 7a 6d [2] 48 4f [2] 4e 7a [2] 60 7a [2] 5f 66 }

  condition:
    any of them
}