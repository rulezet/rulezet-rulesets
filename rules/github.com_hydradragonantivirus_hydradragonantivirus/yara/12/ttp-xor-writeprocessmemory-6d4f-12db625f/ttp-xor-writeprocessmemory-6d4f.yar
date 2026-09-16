rule TTP_XOR_WriteProcessMemory_6d4f {
  strings:
    $key_6d4f = { 3a 3d [2] 08 1f [2] 0e 2a [2] 20 2a [2] 1f 36 }

  condition:
    any of them
}