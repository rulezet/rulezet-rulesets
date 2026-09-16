rule TTP_XOR_WriteProcessMemory_702d {
  strings:
    $key_702d = { 27 5f [2] 15 7d [2] 13 48 [2] 3d 48 [2] 02 54 }

  condition:
    any of them
}