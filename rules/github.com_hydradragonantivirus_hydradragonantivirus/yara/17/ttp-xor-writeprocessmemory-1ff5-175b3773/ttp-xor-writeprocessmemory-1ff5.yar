rule TTP_XOR_WriteProcessMemory_1ff5 {
  strings:
    $key_1ff5 = { 48 87 [2] 7a a5 [2] 7c 90 [2] 52 90 [2] 6d 8c }

  condition:
    any of them
}