rule TTP_XOR_WriteProcessMemory_3323 {
  strings:
    $key_3323 = { 64 51 [2] 56 73 [2] 50 46 [2] 7e 46 [2] 41 5a }

  condition:
    any of them
}