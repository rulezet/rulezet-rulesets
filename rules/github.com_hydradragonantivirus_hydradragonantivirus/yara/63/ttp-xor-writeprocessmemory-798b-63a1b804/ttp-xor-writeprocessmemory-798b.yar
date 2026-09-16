rule TTP_XOR_WriteProcessMemory_798b {
  strings:
    $key_798b = { 2e f9 [2] 1c db [2] 1a ee [2] 34 ee [2] 0b f2 }

  condition:
    any of them
}