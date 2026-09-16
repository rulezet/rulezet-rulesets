rule TTP_XOR_WriteProcessMemory_4857 {
  strings:
    $key_4857 = { 1f 25 [2] 2d 07 [2] 2b 32 [2] 05 32 [2] 3a 2e }

  condition:
    any of them
}