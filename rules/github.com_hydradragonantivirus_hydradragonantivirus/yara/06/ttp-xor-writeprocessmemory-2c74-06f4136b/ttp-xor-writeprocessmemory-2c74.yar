rule TTP_XOR_WriteProcessMemory_2c74 {
  strings:
    $key_2c74 = { 7b 06 [2] 49 24 [2] 4f 11 [2] 61 11 [2] 5e 0d }

  condition:
    any of them
}