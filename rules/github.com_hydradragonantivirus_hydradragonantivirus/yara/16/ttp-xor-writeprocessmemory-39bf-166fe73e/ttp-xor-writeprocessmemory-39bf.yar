rule TTP_XOR_WriteProcessMemory_39bf {
  strings:
    $key_39bf = { 6e cd [2] 5c ef [2] 5a da [2] 74 da [2] 4b c6 }

  condition:
    any of them
}