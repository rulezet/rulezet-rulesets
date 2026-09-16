rule TTP_XOR_WriteProcessMemory_e802 {
  strings:
    $key_e802 = { bf 70 [2] 8d 52 [2] 8b 67 [2] a5 67 [2] 9a 7b }

  condition:
    any of them
}