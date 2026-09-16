rule TTP_XOR_WriteProcessMemory_703f {
  strings:
    $key_703f = { 27 4d [2] 15 6f [2] 13 5a [2] 3d 5a [2] 02 46 }

  condition:
    any of them
}