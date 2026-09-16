rule TTP_XOR_WriteProcessMemory_3057 {
  strings:
    $key_3057 = { 67 25 [2] 55 07 [2] 53 32 [2] 7d 32 [2] 42 2e }

  condition:
    any of them
}