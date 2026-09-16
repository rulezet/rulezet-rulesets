rule TTP_XOR_WriteProcessMemory_235d {
  strings:
    $key_235d = { 74 2f [2] 46 0d [2] 40 38 [2] 6e 38 [2] 51 24 }

  condition:
    any of them
}