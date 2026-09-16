rule TTP_XOR_WriteProcessMemory_2c04 {
  strings:
    $key_2c04 = { 7b 76 [2] 49 54 [2] 4f 61 [2] 61 61 [2] 5e 7d }

  condition:
    any of them
}