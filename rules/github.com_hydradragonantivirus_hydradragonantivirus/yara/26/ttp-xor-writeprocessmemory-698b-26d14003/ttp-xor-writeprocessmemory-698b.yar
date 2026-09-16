rule TTP_XOR_WriteProcessMemory_698b {
  strings:
    $key_698b = { 3e f9 [2] 0c db [2] 0a ee [2] 24 ee [2] 1b f2 }

  condition:
    any of them
}