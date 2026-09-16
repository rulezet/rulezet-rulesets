rule TTP_XOR_WriteProcessMemory_4127 {
  strings:
    $key_4127 = { 16 55 [2] 24 77 [2] 22 42 [2] 0c 42 [2] 33 5e }

  condition:
    any of them
}