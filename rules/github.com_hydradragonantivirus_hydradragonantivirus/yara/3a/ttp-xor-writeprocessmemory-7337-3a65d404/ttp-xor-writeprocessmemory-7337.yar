rule TTP_XOR_WriteProcessMemory_7337 {
  strings:
    $key_7337 = { 24 45 [2] 16 67 [2] 10 52 [2] 3e 52 [2] 01 4e }

  condition:
    any of them
}