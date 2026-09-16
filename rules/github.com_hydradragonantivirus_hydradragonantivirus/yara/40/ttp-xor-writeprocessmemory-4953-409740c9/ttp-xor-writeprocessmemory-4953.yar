rule TTP_XOR_WriteProcessMemory_4953 {
  strings:
    $key_4953 = { 1e 21 [2] 2c 03 [2] 2a 36 [2] 04 36 [2] 3b 2a }

  condition:
    any of them
}