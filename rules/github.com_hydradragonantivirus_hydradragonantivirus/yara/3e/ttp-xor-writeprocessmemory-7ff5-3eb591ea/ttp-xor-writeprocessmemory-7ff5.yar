rule TTP_XOR_WriteProcessMemory_7ff5 {
  strings:
    $key_7ff5 = { 28 87 [2] 1a a5 [2] 1c 90 [2] 32 90 [2] 0d 8c }

  condition:
    any of them
}