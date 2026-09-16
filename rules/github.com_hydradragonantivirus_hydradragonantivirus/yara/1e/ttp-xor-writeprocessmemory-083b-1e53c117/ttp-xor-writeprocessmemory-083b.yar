rule TTP_XOR_WriteProcessMemory_083b {
  strings:
    $key_083b = { 5f 49 [2] 6d 6b [2] 6b 5e [2] 45 5e [2] 7a 42 }

  condition:
    any of them
}