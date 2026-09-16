rule TTP_XOR_WriteProcessMemory_4e74 {
  strings:
    $key_4e74 = { 19 06 [2] 2b 24 [2] 2d 11 [2] 03 11 [2] 3c 0d }

  condition:
    any of them
}