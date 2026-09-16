rule TTP_XOR_WriteProcessMemory_3f57 {
  strings:
    $key_3f57 = { 68 25 [2] 5a 07 [2] 5c 32 [2] 72 32 [2] 4d 2e }

  condition:
    any of them
}