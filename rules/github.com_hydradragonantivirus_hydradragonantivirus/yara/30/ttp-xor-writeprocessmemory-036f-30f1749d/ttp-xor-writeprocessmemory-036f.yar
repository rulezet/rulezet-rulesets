rule TTP_XOR_WriteProcessMemory_036f {
  strings:
    $key_036f = { 54 1d [2] 66 3f [2] 60 0a [2] 4e 0a [2] 71 16 }

  condition:
    any of them
}