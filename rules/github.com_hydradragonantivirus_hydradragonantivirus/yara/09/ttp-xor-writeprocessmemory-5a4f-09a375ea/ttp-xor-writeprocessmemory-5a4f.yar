rule TTP_XOR_WriteProcessMemory_5a4f {
  strings:
    $key_5a4f = { 0d 3d [2] 3f 1f [2] 39 2a [2] 17 2a [2] 28 36 }

  condition:
    any of them
}