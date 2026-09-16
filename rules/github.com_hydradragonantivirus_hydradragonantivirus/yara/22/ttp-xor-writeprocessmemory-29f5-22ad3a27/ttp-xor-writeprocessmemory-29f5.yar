rule TTP_XOR_WriteProcessMemory_29f5 {
  strings:
    $key_29f5 = { 7e 87 [2] 4c a5 [2] 4a 90 [2] 64 90 [2] 5b 8c }

  condition:
    any of them
}