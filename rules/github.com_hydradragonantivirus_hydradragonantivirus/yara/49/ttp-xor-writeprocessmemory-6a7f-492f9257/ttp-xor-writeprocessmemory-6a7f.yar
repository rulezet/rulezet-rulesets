rule TTP_XOR_WriteProcessMemory_6a7f {
  strings:
    $key_6a7f = { 3d 0d [2] 0f 2f [2] 09 1a [2] 27 1a [2] 18 06 }

  condition:
    any of them
}