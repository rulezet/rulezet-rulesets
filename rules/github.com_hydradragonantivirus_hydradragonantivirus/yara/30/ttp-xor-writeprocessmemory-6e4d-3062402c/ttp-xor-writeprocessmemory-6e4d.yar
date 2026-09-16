rule TTP_XOR_WriteProcessMemory_6e4d {
  strings:
    $key_6e4d = { 39 3f [2] 0b 1d [2] 0d 28 [2] 23 28 [2] 1c 34 }

  condition:
    any of them
}