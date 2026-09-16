rule TTP_XOR_WriteProcessMemory_3e9c {
  strings:
    $key_3e9c = { 69 ee [2] 5b cc [2] 5d f9 [2] 73 f9 [2] 4c e5 }

  condition:
    any of them
}