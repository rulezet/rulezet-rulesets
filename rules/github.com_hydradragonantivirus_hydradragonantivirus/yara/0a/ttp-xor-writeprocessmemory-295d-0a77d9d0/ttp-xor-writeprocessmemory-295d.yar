rule TTP_XOR_WriteProcessMemory_295d {
  strings:
    $key_295d = { 7e 2f [2] 4c 0d [2] 4a 38 [2] 64 38 [2] 5b 24 }

  condition:
    any of them
}