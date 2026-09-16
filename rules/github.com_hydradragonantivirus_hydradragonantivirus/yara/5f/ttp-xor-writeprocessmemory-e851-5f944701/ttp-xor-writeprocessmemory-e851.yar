rule TTP_XOR_WriteProcessMemory_e851 {
  strings:
    $key_e851 = { bf 23 [2] 8d 01 [2] 8b 34 [2] a5 34 [2] 9a 28 }

  condition:
    any of them
}