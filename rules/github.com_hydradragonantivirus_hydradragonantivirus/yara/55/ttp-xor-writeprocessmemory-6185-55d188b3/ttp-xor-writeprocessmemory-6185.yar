rule TTP_XOR_WriteProcessMemory_6185 {
  strings:
    $key_6185 = { 36 f7 [2] 04 d5 [2] 02 e0 [2] 2c e0 [2] 13 fc }

  condition:
    any of them
}