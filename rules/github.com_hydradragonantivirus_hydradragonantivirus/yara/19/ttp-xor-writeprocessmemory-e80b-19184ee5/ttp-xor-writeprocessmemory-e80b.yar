rule TTP_XOR_WriteProcessMemory_e80b {
  strings:
    $key_e80b = { bf 79 [2] 8d 5b [2] 8b 6e [2] a5 6e [2] 9a 72 }

  condition:
    any of them
}