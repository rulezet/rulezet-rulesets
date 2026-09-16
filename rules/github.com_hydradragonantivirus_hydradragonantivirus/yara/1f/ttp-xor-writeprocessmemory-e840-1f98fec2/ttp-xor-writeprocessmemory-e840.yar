rule TTP_XOR_WriteProcessMemory_e840 {
  strings:
    $key_e840 = { bf 32 [2] 8d 10 [2] 8b 25 [2] a5 25 [2] 9a 39 }

  condition:
    any of them
}