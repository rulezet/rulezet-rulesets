rule TTP_XOR_WriteProcessMemory_2d0f {
  strings:
    $key_2d0f = { 7a 7d [2] 48 5f [2] 4e 6a [2] 60 6a [2] 5f 76 }

  condition:
    any of them
}