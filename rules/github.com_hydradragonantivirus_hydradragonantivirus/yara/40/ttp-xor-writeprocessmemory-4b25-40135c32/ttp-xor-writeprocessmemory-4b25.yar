rule TTP_XOR_WriteProcessMemory_4b25 {
  strings:
    $key_4b25 = { 1c 57 [2] 2e 75 [2] 28 40 [2] 06 40 [2] 39 5c }

  condition:
    any of them
}