rule TTP_XOR_WriteProcessMemory_3523 {
  strings:
    $key_3523 = { 62 51 [2] 50 73 [2] 56 46 [2] 78 46 [2] 47 5a }

  condition:
    any of them
}