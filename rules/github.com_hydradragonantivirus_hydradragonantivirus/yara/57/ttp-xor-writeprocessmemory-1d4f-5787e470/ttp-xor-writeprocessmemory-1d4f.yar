rule TTP_XOR_WriteProcessMemory_1d4f {
  strings:
    $key_1d4f = { 4a 3d [2] 78 1f [2] 7e 2a [2] 50 2a [2] 6f 36 }

  condition:
    any of them
}