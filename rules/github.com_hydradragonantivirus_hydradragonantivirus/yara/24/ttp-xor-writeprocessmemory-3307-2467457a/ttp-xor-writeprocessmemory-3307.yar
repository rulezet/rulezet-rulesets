rule TTP_XOR_WriteProcessMemory_3307 {
  strings:
    $key_3307 = { 64 75 [2] 56 57 [2] 50 62 [2] 7e 62 [2] 41 7e }

  condition:
    any of them
}