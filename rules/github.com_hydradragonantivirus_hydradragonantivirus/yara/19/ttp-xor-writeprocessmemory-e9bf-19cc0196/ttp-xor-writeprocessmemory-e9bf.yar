rule TTP_XOR_WriteProcessMemory_e9bf {
  strings:
    $key_e9bf = { be cd [2] 8c ef [2] 8a da [2] a4 da [2] 9b c6 }

  condition:
    any of them
}