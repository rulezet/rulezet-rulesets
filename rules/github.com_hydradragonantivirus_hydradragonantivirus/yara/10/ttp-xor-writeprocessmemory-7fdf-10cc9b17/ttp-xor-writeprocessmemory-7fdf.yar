rule TTP_XOR_WriteProcessMemory_7fdf {
  strings:
    $key_7fdf = { 28 ad [2] 1a 8f [2] 1c ba [2] 32 ba [2] 0d a6 }

  condition:
    any of them
}