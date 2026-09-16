rule TTP_XOR_WriteProcessMemory_d88b {
  strings:
    $key_d88b = { 8f f9 [2] bd db [2] bb ee [2] 95 ee [2] aa f2 }

  condition:
    any of them
}