rule TTP_XOR_WriteProcessMemory_5637 {
  strings:
    $key_5637 = { 01 45 [2] 33 67 [2] 35 52 [2] 1b 52 [2] 24 4e }

  condition:
    any of them
}