rule TTP_XOR_WriteProcessMemory_1304 {
  strings:
    $key_1304 = { 44 76 [2] 76 54 [2] 70 61 [2] 5e 61 [2] 61 7d }

  condition:
    any of them
}