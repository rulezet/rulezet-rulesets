rule TTP_XOR_WriteProcessMemory_3d6f {
  strings:
    $key_3d6f = { 6a 1d [2] 58 3f [2] 5e 0a [2] 70 0a [2] 4f 16 }

  condition:
    any of them
}