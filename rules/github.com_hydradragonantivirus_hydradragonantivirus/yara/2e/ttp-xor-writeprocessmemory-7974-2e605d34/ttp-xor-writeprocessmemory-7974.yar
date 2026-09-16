rule TTP_XOR_WriteProcessMemory_7974 {
  strings:
    $key_7974 = { 2e 06 [2] 1c 24 [2] 1a 11 [2] 34 11 [2] 0b 0d }

  condition:
    any of them
}