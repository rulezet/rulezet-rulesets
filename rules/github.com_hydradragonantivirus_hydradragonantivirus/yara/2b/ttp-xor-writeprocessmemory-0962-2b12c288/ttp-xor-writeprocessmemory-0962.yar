rule TTP_XOR_WriteProcessMemory_0962 {
  strings:
    $key_0962 = { 5e 10 [2] 6c 32 [2] 6a 07 [2] 44 07 [2] 7b 1b }

  condition:
    any of them
}