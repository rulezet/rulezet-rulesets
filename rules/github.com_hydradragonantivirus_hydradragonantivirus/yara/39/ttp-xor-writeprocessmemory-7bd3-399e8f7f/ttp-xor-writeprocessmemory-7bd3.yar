rule TTP_XOR_WriteProcessMemory_7bd3 {
  strings:
    $key_7bd3 = { 2c a1 [2] 1e 83 [2] 18 b6 [2] 36 b6 [2] 09 aa }

  condition:
    any of them
}