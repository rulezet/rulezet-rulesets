rule TTP_XOR_WriteProcessMemory_755d {
  strings:
    $key_755d = { 22 2f [2] 10 0d [2] 16 38 [2] 38 38 [2] 07 24 }

  condition:
    any of them
}