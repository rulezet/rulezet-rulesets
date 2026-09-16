rule TTP_XOR_WriteProcessMemory_6a6f {
  strings:
    $key_6a6f = { 3d 1d [2] 0f 3f [2] 09 0a [2] 27 0a [2] 18 16 }

  condition:
    any of them
}