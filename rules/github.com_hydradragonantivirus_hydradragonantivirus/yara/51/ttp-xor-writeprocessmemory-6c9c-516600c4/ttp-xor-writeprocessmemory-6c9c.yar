rule TTP_XOR_WriteProcessMemory_6c9c {
  strings:
    $key_6c9c = { 3b ee [2] 09 cc [2] 0f f9 [2] 21 f9 [2] 1e e5 }

  condition:
    any of them
}