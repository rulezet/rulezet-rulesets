rule TTP_XOR_WriteProcessMemory_447d {
  strings:
    $key_447d = { 13 0f [2] 21 2d [2] 27 18 [2] 09 18 [2] 36 04 }

  condition:
    any of them
}