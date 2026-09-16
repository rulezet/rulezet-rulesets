rule TTP_XOR_WriteProcessMemory_e83b {
  strings:
    $key_e83b = { bf 49 [2] 8d 6b [2] 8b 5e [2] a5 5e [2] 9a 42 }

  condition:
    any of them
}