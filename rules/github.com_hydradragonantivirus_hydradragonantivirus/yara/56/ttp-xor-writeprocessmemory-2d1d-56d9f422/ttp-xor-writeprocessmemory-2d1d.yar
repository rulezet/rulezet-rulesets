rule TTP_XOR_WriteProcessMemory_2d1d {
  strings:
    $key_2d1d = { 7a 6f [2] 48 4d [2] 4e 78 [2] 60 78 [2] 5f 64 }

  condition:
    any of them
}