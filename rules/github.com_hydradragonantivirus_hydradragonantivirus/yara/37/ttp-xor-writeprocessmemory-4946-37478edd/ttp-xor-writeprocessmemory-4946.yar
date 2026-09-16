rule TTP_XOR_WriteProcessMemory_4946 {
  strings:
    $key_4946 = { 1e 34 [2] 2c 16 [2] 2a 23 [2] 04 23 [2] 3b 3f }

  condition:
    any of them
}