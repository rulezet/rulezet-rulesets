rule TTP_XOR_WriteProcessMemory_e864 {
  strings:
    $key_e864 = { bf 16 [2] 8d 34 [2] 8b 01 [2] a5 01 [2] 9a 1d }

  condition:
    any of them
}