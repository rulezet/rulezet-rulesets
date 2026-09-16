rule TTP_XOR_WriteProcessMemory_3d7f {
  strings:
    $key_3d7f = { 6a 0d [2] 58 2f [2] 5e 1a [2] 70 1a [2] 4f 06 }

  condition:
    any of them
}