rule TTP_XOR_WriteProcessMemory_7018 {
  strings:
    $key_7018 = { 27 6a [2] 15 48 [2] 13 7d [2] 3d 7d [2] 02 61 }

  condition:
    any of them
}