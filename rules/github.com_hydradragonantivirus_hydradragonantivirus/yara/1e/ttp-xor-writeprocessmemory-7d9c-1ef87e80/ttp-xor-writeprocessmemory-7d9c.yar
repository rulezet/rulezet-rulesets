rule TTP_XOR_WriteProcessMemory_7d9c {
  strings:
    $key_7d9c = { 2a ee [2] 18 cc [2] 1e f9 [2] 30 f9 [2] 0f e5 }

  condition:
    any of them
}