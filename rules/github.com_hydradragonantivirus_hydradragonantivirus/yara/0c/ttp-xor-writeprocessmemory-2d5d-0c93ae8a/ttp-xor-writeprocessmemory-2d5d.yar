rule TTP_XOR_WriteProcessMemory_2d5d {
  strings:
    $key_2d5d = { 7a 2f [2] 48 0d [2] 4e 38 [2] 60 38 [2] 5f 24 }

  condition:
    any of them
}