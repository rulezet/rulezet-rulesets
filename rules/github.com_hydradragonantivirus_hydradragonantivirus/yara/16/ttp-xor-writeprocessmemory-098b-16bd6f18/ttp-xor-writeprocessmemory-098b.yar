rule TTP_XOR_WriteProcessMemory_098b {
  strings:
    $key_098b = { 5e f9 [2] 6c db [2] 6a ee [2] 44 ee [2] 7b f2 }

  condition:
    any of them
}