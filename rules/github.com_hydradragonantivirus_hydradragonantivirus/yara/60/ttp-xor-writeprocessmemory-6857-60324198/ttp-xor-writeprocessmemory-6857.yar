rule TTP_XOR_WriteProcessMemory_6857 {
  strings:
    $key_6857 = { 3f 25 [2] 0d 07 [2] 0b 32 [2] 25 32 [2] 1a 2e }

  condition:
    any of them
}