rule TTP_XOR_WriteProcessMemory_154d {
  strings:
    $key_154d = { 42 3f [2] 70 1d [2] 76 28 [2] 58 28 [2] 67 34 }

  condition:
    any of them
}