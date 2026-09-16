rule TTP_XOR_WriteProcessMemory_185d {
  strings:
    $key_185d = { 4f 2f [2] 7d 0d [2] 7b 38 [2] 55 38 [2] 6a 24 }

  condition:
    any of them
}