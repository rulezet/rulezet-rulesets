rule TTP_XOR_WriteProcessMemory_e862 {
  strings:
    $key_e862 = { bf 10 [2] 8d 32 [2] 8b 07 [2] a5 07 [2] 9a 1b }

  condition:
    any of them
}