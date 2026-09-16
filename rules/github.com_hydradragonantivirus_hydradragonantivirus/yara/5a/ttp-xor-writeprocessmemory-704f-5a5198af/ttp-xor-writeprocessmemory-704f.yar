rule TTP_XOR_WriteProcessMemory_704f {
  strings:
    $key_704f = { 27 3d [2] 15 1f [2] 13 2a [2] 3d 2a [2] 02 36 }

  condition:
    any of them
}