rule TTP_XOR_WriteProcessMemory_29bf {
  strings:
    $key_29bf = { 7e cd [2] 4c ef [2] 4a da [2] 64 da [2] 5b c6 }

  condition:
    any of them
}