rule TTP_XOR_WriteProcessMemory_e863 {
  strings:
    $key_e863 = { bf 11 [2] 8d 33 [2] 8b 06 [2] a5 06 [2] 9a 1a }

  condition:
    any of them
}