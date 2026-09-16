rule TTP_XOR_WriteProcessMemory_e85b {
  strings:
    $key_e85b = { bf 29 [2] 8d 0b [2] 8b 3e [2] a5 3e [2] 9a 22 }

  condition:
    any of them
}