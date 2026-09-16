rule TTP_XOR_WriteProcessMemory_e800 {
  strings:
    $key_e800 = { bf 72 [2] 8d 50 [2] 8b 65 [2] a5 65 [2] 9a 79 }

  condition:
    any of them
}