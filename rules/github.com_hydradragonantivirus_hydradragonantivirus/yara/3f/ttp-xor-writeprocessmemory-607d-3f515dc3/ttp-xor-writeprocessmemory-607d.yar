rule TTP_XOR_WriteProcessMemory_607d {
  strings:
    $key_607d = { 37 0f [2] 05 2d [2] 03 18 [2] 2d 18 [2] 12 04 }

  condition:
    any of them
}