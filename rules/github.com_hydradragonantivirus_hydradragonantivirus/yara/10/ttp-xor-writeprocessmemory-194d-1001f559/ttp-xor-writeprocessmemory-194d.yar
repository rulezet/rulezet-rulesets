rule TTP_XOR_WriteProcessMemory_194d {
  strings:
    $key_194d = { 4e 3f [2] 7c 1d [2] 7a 28 [2] 54 28 [2] 6b 34 }

  condition:
    any of them
}