rule TTP_XOR_WriteProcessMemory_4fdf {
  strings:
    $key_4fdf = { 18 ad [2] 2a 8f [2] 2c ba [2] 02 ba [2] 3d a6 }

  condition:
    any of them
}