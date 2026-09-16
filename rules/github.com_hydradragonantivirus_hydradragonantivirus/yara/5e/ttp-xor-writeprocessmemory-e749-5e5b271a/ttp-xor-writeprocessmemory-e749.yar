rule TTP_XOR_WriteProcessMemory_e749 {
  strings:
    $key_e749 = { b0 3b [2] 82 19 [2] 84 2c [2] aa 2c [2] 95 30 }

  condition:
    any of them
}