rule TTP_XOR_WriteProcessMemory_2f7d {
  strings:
    $key_2f7d = { 78 0f [2] 4a 2d [2] 4c 18 [2] 62 18 [2] 5d 04 }

  condition:
    any of them
}