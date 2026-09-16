rule TTP_XOR_WriteProcessMemory_e855 {
  strings:
    $key_e855 = { bf 27 [2] 8d 05 [2] 8b 30 [2] a5 30 [2] 9a 2c }

  condition:
    any of them
}