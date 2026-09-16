rule TTP_XOR_WriteProcessMemory_503d {
  strings:
    $key_503d = { 07 4f [2] 35 6d [2] 33 58 [2] 1d 58 [2] 22 44 }

  condition:
    any of them
}