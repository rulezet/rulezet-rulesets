rule TTP_XOR_WriteProcessMemory_2d0d {
  strings:
    $key_2d0d = { 7a 7f [2] 48 5d [2] 4e 68 [2] 60 68 [2] 5f 74 }

  condition:
    any of them
}