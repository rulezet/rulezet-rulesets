rule TTP_XOR_WriteProcessMemory_236d {
  strings:
    $key_236d = { 74 1f [2] 46 3d [2] 40 08 [2] 6e 08 [2] 51 14 }

  condition:
    any of them
}