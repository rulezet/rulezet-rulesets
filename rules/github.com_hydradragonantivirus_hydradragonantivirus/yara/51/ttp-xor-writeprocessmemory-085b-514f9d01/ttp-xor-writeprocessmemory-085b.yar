rule TTP_XOR_WriteProcessMemory_085b {
  strings:
    $key_085b = { 5f 29 [2] 6d 0b [2] 6b 3e [2] 45 3e [2] 7a 22 }

  condition:
    any of them
}