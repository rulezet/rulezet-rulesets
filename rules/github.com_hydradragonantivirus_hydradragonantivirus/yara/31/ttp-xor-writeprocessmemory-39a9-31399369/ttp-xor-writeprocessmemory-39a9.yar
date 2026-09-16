rule TTP_XOR_WriteProcessMemory_39a9 {
  strings:
    $key_39a9 = { 6e db [2] 5c f9 [2] 5a cc [2] 74 cc [2] 4b d0 }

  condition:
    any of them
}