rule TTP_XOR_WriteProcessMemory_0e74 {
  strings:
    $key_0e74 = { 59 06 [2] 6b 24 [2] 6d 11 [2] 43 11 [2] 7c 0d }

  condition:
    any of them
}