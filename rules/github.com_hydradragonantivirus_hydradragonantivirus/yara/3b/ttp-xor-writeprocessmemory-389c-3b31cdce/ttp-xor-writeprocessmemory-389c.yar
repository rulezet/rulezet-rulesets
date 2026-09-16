rule TTP_XOR_WriteProcessMemory_389c {
  strings:
    $key_389c = { 6f ee [2] 5d cc [2] 5b f9 [2] 75 f9 [2] 4a e5 }

  condition:
    any of them
}