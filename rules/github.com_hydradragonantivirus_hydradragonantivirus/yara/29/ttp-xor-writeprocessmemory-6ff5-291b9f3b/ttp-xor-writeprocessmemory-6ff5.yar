rule TTP_XOR_WriteProcessMemory_6ff5 {
  strings:
    $key_6ff5 = { 38 87 [2] 0a a5 [2] 0c 90 [2] 22 90 [2] 1d 8c }

  condition:
    any of them
}