rule TTP_XOR_WriteProcessMemory_2f57 {
  strings:
    $key_2f57 = { 78 25 [2] 4a 07 [2] 4c 32 [2] 62 32 [2] 5d 2e }

  condition:
    any of them
}