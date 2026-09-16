rule TTP_XOR_WriteProcessMemory_4937 {
  strings:
    $key_4937 = { 1e 45 [2] 2c 67 [2] 2a 52 [2] 04 52 [2] 3b 4e }

  condition:
    any of them
}