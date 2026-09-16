rule TTP_XOR_WriteProcessMemory_7d07 {
  strings:
    $key_7d07 = { 2a 75 [2] 18 57 [2] 1e 62 [2] 30 62 [2] 0f 7e }

  condition:
    any of them
}