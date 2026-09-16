rule TTP_XOR_WriteProcessMemory_19bf {
  strings:
    $key_19bf = { 4e cd [2] 7c ef [2] 7a da [2] 54 da [2] 6b c6 }

  condition:
    any of them
}