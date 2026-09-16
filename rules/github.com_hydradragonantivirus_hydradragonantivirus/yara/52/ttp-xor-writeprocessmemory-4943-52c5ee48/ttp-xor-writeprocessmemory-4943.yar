rule TTP_XOR_WriteProcessMemory_4943 {
  strings:
    $key_4943 = { 1e 31 [2] 2c 13 [2] 2a 26 [2] 04 26 [2] 3b 3a }

  condition:
    any of them
}