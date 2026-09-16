rule TTP_XOR_WriteProcessMemory_700f {
  strings:
    $key_700f = { 27 7d [2] 15 5f [2] 13 6a [2] 3d 6a [2] 02 76 }

  condition:
    any of them
}