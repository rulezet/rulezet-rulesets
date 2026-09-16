rule TTP_XOR_WriteProcessMemory_5d4f {
  strings:
    $key_5d4f = { 0a 3d [2] 38 1f [2] 3e 2a [2] 10 2a [2] 2f 36 }

  condition:
    any of them
}