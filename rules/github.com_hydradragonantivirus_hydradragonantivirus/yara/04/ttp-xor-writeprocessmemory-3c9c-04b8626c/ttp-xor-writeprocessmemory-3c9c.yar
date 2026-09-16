rule TTP_XOR_WriteProcessMemory_3c9c {
  strings:
    $key_3c9c = { 6b ee [2] 59 cc [2] 5f f9 [2] 71 f9 [2] 4e e5 }

  condition:
    any of them
}