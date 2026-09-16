rule TTP_XOR_WriteProcessMemory_607a {
  strings:
    $key_607a = { 37 08 [2] 05 2a [2] 03 1f [2] 2d 1f [2] 12 03 }

  condition:
    any of them
}