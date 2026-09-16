rule TTP_XOR_WriteProcessMemory_e872 {
  strings:
    $key_e872 = { bf 00 [2] 8d 22 [2] 8b 17 [2] a5 17 [2] 9a 0b }

  condition:
    any of them
}