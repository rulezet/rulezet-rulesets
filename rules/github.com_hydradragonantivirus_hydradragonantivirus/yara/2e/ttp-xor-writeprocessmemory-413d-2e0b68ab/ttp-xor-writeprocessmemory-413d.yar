rule TTP_XOR_WriteProcessMemory_413d {
  strings:
    $key_413d = { 16 4f [2] 24 6d [2] 22 58 [2] 0c 58 [2] 33 44 }

  condition:
    any of them
}