rule TTP_XOR_WriteProcessMemory_2d4d {
  strings:
    $key_2d4d = { 7a 3f [2] 48 1d [2] 4e 28 [2] 60 28 [2] 5f 34 }

  condition:
    any of them
}