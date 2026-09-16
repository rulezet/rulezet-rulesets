rule TTP_XOR_WriteProcessMemory_09bf {
  strings:
    $key_09bf = { 5e cd [2] 6c ef [2] 6a da [2] 44 da [2] 7b c6 }

  condition:
    any of them
}