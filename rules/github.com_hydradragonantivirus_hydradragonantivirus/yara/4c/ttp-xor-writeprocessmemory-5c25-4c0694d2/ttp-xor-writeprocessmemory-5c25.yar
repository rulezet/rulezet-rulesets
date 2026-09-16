rule TTP_XOR_WriteProcessMemory_5c25 {
  strings:
    $key_5c25 = { 0b 57 [2] 39 75 [2] 3f 40 [2] 11 40 [2] 2e 5c }

  condition:
    any of them
}