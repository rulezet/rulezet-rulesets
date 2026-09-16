rule TTP_XOR_WriteProcessMemory_0857 {
  strings:
    $key_0857 = { 5f 25 [2] 6d 07 [2] 6b 32 [2] 45 32 [2] 7a 2e }

  condition:
    any of them
}