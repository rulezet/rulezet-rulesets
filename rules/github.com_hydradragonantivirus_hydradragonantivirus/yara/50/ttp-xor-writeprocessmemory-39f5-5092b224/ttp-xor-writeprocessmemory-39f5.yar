rule TTP_XOR_WriteProcessMemory_39f5 {
  strings:
    $key_39f5 = { 6e 87 [2] 5c a5 [2] 5a 90 [2] 74 90 [2] 4b 8c }

  condition:
    any of them
}