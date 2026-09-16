rule TTP_XOR_WriteProcessMemory_7347 {
  strings:
    $key_7347 = { 24 35 [2] 16 17 [2] 10 22 [2] 3e 22 [2] 01 3e }

  condition:
    any of them
}