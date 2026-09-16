rule TTP_XOR_WriteProcessMemory_7323 {
  strings:
    $key_7323 = { 24 51 [2] 16 73 [2] 10 46 [2] 3e 46 [2] 01 5a }

  condition:
    any of them
}