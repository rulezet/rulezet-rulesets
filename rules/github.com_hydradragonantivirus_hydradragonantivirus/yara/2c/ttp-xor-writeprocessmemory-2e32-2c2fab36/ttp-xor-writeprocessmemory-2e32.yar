rule TTP_XOR_WriteProcessMemory_2e32 {
  strings:
    $key_2e32 = { 79 40 [2] 4b 62 [2] 4d 57 [2] 63 57 [2] 5c 4b }

  condition:
    any of them
}