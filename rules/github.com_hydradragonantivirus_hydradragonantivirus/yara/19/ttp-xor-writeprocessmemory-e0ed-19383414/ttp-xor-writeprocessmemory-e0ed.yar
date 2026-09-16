rule TTP_XOR_WriteProcessMemory_e0ed {
  strings:
    $key_e0ed = { b7 9f [2] 85 bd [2] 83 88 [2] ad 88 [2] 92 94 }

  condition:
    any of them
}