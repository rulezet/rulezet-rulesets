rule TTP_XOR_WriteProcessMemory_4734 {
  strings:
    $key_4734 = { 10 46 [2] 22 64 [2] 24 51 [2] 0a 51 [2] 35 4d }

  condition:
    any of them
}