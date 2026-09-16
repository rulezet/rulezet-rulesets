rule TTP_XOR_WriteProcessMemory_1c9c {
  strings:
    $key_1c9c = { 4b ee [2] 79 cc [2] 7f f9 [2] 51 f9 [2] 6e e5 }

  condition:
    any of them
}