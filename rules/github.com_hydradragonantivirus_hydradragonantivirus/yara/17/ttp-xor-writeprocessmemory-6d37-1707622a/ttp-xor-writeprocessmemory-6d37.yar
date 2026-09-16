rule TTP_XOR_WriteProcessMemory_6d37 {
  strings:
    $key_6d37 = { 3a 45 [2] 08 67 [2] 0e 52 [2] 20 52 [2] 1f 4e }

  condition:
    any of them
}