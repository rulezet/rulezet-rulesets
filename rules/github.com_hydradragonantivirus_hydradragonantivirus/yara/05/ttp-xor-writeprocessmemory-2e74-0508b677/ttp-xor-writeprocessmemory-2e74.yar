rule TTP_XOR_WriteProcessMemory_2e74 {
  strings:
    $key_2e74 = { 79 06 [2] 4b 24 [2] 4d 11 [2] 63 11 [2] 5c 0d }

  condition:
    any of them
}