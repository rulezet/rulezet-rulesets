rule TTP_XOR_WriteProcessMemory_e722 {
  strings:
    $key_e722 = { b0 50 [2] 82 72 [2] 84 47 [2] aa 47 [2] 95 5b }

  condition:
    any of them
}