rule TTP_XOR_WriteProcessMemory_2f2d {
  strings:
    $key_2f2d = { 78 5f [2] 4a 7d [2] 4c 48 [2] 62 48 [2] 5d 54 }

  condition:
    any of them
}