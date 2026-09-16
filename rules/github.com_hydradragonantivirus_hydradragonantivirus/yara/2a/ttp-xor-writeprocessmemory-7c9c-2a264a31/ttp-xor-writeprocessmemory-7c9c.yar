rule TTP_XOR_WriteProcessMemory_7c9c {
  strings:
    $key_7c9c = { 2b ee [2] 19 cc [2] 1f f9 [2] 31 f9 [2] 0e e5 }

  condition:
    any of them
}