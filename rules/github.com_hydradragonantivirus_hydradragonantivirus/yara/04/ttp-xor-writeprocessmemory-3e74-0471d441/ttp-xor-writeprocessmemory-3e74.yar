rule TTP_XOR_WriteProcessMemory_3e74 {
  strings:
    $key_3e74 = { 69 06 [2] 5b 24 [2] 5d 11 [2] 73 11 [2] 4c 0d }

  condition:
    any of them
}