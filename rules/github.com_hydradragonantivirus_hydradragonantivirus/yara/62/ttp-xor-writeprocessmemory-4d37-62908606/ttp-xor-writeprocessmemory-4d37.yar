rule TTP_XOR_WriteProcessMemory_4d37 {
  strings:
    $key_4d37 = { 1a 45 [2] 28 67 [2] 2e 52 [2] 00 52 [2] 3f 4e }

  condition:
    any of them
}