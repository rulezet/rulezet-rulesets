rule TTP_XOR_WriteProcessMemory_7a4d {
  strings:
    $key_7a4d = { 2d 3f [2] 1f 1d [2] 19 28 [2] 37 28 [2] 08 34 }

  condition:
    any of them
}