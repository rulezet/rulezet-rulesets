rule TTP_XOR_WriteProcessMemory_e820 {
  strings:
    $key_e820 = { bf 52 [2] 8d 70 [2] 8b 45 [2] a5 45 [2] 9a 59 }

  condition:
    any of them
}