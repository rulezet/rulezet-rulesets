rule TTP_XOR_WriteProcessMemory_e832 {
  strings:
    $key_e832 = { bf 40 [2] 8d 62 [2] 8b 57 [2] a5 57 [2] 9a 4b }

  condition:
    any of them
}