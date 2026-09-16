rule TTP_XOR_WriteProcessMemory_4931 {
  strings:
    $key_4931 = { 1e 43 [2] 2c 61 [2] 2a 54 [2] 04 54 [2] 3b 48 }

  condition:
    any of them
}