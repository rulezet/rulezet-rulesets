rule TTP_XOR_WriteProcessMemory_70ff {
  strings:
    $key_70ff = { 27 8d [2] 15 af [2] 13 9a [2] 3d 9a [2] 02 86 }

  condition:
    any of them
}