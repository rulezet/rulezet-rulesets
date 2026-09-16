rule TTP_XOR_WriteProcessMemory_498b {
  strings:
    $key_498b = { 1e f9 [2] 2c db [2] 2a ee [2] 04 ee [2] 3b f2 }

  condition:
    any of them
}