rule TTP_XOR_WriteProcessMemory_4337 {
  strings:
    $key_4337 = { 14 45 [2] 26 67 [2] 20 52 [2] 0e 52 [2] 31 4e }

  condition:
    any of them
}