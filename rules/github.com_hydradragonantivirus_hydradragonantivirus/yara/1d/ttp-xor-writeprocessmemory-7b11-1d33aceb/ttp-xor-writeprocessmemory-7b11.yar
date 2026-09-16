rule TTP_XOR_WriteProcessMemory_7b11 {
  strings:
    $key_7b11 = { 2c 63 [2] 1e 41 [2] 18 74 [2] 36 74 [2] 09 68 }

  condition:
    any of them
}