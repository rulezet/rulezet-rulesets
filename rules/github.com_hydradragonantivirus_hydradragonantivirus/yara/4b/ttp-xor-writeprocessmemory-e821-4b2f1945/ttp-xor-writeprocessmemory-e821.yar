rule TTP_XOR_WriteProcessMemory_e821 {
  strings:
    $key_e821 = { bf 53 [2] 8d 71 [2] 8b 44 [2] a5 44 [2] 9a 58 }

  condition:
    any of them
}