rule TTP_XOR_WriteProcessMemory_7a1d {
  strings:
    $key_7a1d = { 2d 6f [2] 1f 4d [2] 19 78 [2] 37 78 [2] 08 64 }

  condition:
    any of them
}