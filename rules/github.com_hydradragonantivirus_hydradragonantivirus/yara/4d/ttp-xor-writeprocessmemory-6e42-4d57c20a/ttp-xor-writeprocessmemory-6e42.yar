rule TTP_XOR_WriteProcessMemory_6e42 {
  strings:
    $key_6e42 = { 39 30 [2] 0b 12 [2] 0d 27 [2] 23 27 [2] 1c 3b }

  condition:
    any of them
}