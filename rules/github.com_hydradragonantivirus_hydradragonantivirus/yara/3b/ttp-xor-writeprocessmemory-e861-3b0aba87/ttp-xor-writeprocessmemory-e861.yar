rule TTP_XOR_WriteProcessMemory_e861 {
  strings:
    $key_e861 = { bf 13 [2] 8d 31 [2] 8b 04 [2] a5 04 [2] 9a 18 }

  condition:
    any of them
}