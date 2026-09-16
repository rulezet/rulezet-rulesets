rule TTP_XOR_WriteProcessMemory_4c9c {
  strings:
    $key_4c9c = { 1b ee [2] 29 cc [2] 2f f9 [2] 01 f9 [2] 3e e5 }

  condition:
    any of them
}