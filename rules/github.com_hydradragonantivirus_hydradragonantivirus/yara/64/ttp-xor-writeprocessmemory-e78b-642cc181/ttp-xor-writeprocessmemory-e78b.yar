rule TTP_XOR_WriteProcessMemory_e78b {
  strings:
    $key_e78b = { b0 f9 [2] 82 db [2] 84 ee [2] aa ee [2] 95 f2 }

  condition:
    any of them
}