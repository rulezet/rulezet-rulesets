rule TTP_XOR_WriteProcessMemory_7864 {
  strings:
    $key_7864 = { 2f 16 [2] 1d 34 [2] 1b 01 [2] 35 01 [2] 0a 1d }

  condition:
    any of them
}