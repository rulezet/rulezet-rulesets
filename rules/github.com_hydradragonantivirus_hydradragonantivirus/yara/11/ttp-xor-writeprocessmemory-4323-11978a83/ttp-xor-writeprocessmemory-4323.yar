rule TTP_XOR_WriteProcessMemory_4323 {
  strings:
    $key_4323 = { 14 51 [2] 26 73 [2] 20 46 [2] 0e 46 [2] 31 5a }

  condition:
    any of them
}