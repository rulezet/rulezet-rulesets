rule TTP_XOR_WriteProcessMemory_e826 {
  strings:
    $key_e826 = { bf 54 [2] 8d 76 [2] 8b 43 [2] a5 43 [2] 9a 5f }

  condition:
    any of them
}