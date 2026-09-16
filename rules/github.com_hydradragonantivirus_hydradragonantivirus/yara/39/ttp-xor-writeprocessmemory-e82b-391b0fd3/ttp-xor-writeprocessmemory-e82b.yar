rule TTP_XOR_WriteProcessMemory_e82b {
  strings:
    $key_e82b = { bf 59 [2] 8d 7b [2] 8b 4e [2] a5 4e [2] 9a 52 }

  condition:
    any of them
}