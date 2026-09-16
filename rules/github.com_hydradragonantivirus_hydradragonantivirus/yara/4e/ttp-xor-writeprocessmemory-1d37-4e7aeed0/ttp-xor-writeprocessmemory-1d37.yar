rule TTP_XOR_WriteProcessMemory_1d37 {
  strings:
    $key_1d37 = { 4a 45 [2] 78 67 [2] 7e 52 [2] 50 52 [2] 6f 4e }

  condition:
    any of them
}