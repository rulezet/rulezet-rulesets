rule TTP_XOR_WriteProcessMemory_5fdf {
  strings:
    $key_5fdf = { 08 ad [2] 3a 8f [2] 3c ba [2] 12 ba [2] 2d a6 }

  condition:
    any of them
}