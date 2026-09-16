rule TTP_XOR_WriteProcessMemory_4971 {
  strings:
    $key_4971 = { 1e 03 [2] 2c 21 [2] 2a 14 [2] 04 14 [2] 3b 08 }

  condition:
    any of them
}