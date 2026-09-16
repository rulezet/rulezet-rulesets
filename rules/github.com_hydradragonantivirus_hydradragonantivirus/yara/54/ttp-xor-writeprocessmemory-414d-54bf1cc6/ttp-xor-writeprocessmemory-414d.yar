rule TTP_XOR_WriteProcessMemory_414d {
  strings:
    $key_414d = { 16 3f [2] 24 1d [2] 22 28 [2] 0c 28 [2] 33 34 }

  condition:
    any of them
}