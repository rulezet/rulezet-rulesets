rule TTP_XOR_WriteProcessMemory_dc3b {
  strings:
    $key_dc3b = { 8b 49 [2] b9 6b [2] bf 5e [2] 91 5e [2] ae 42 }

  condition:
    any of them
}