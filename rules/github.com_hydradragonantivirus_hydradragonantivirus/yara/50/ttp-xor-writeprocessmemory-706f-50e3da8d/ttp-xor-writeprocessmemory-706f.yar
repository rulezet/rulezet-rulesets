rule TTP_XOR_WriteProcessMemory_706f {
  strings:
    $key_706f = { 27 1d [2] 15 3f [2] 13 0a [2] 3d 0a [2] 02 16 }

  condition:
    any of them
}