rule TTP_XOR_WriteProcessMemory_e86b {
  strings:
    $key_e86b = { bf 19 [2] 8d 3b [2] 8b 0e [2] a5 0e [2] 9a 12 }

  condition:
    any of them
}