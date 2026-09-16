rule TTP_XOR_WriteProcessMemory_7925 {
  strings:
    $key_7925 = { 2e 57 [2] 1c 75 [2] 1a 40 [2] 34 40 [2] 0b 5c }

  condition:
    any of them
}