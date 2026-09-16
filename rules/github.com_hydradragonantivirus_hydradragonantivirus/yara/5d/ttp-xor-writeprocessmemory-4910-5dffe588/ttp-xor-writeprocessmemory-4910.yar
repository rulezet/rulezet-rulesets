rule TTP_XOR_WriteProcessMemory_4910 {
  strings:
    $key_4910 = { 1e 62 [2] 2c 40 [2] 2a 75 [2] 04 75 [2] 3b 69 }

  condition:
    any of them
}