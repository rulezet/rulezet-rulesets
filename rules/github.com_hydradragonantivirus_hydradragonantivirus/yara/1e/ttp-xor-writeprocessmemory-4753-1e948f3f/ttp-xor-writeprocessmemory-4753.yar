rule TTP_XOR_WriteProcessMemory_4753 {
  strings:
    $key_4753 = { 10 21 [2] 22 03 [2] 24 36 [2] 0a 36 [2] 35 2a }

  condition:
    any of them
}