rule TTP_XOR_WriteProcessMemory_e7e9 {
  strings:
    $key_e7e9 = { b0 9b [2] 82 b9 [2] 84 8c [2] aa 8c [2] 95 90 }

  condition:
    any of them
}