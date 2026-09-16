rule TTP_XOR_WriteProcessMemory_2e9c {
  strings:
    $key_2e9c = { 79 ee [2] 4b cc [2] 4d f9 [2] 63 f9 [2] 5c e5 }

  condition:
    any of them
}