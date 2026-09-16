rule TTP_XOR_WriteProcessMemory_0057 {
  strings:
    $key_0057 = { 57 25 [2] 65 07 [2] 63 32 [2] 4d 32 [2] 72 2e }

  condition:
    any of them
}