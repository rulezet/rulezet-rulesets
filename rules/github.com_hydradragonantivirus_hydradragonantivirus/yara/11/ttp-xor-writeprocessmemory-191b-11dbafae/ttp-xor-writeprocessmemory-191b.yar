rule TTP_XOR_WriteProcessMemory_191b {
  strings:
    $key_191b = { 4e 69 [2] 7c 4b [2] 7a 7e [2] 54 7e [2] 6b 62 }

  condition:
    any of them
}