rule TTP_XOR_WriteProcessMemory_b86b {
  strings:
    $key_b86b = { ef 19 [2] dd 3b [2] db 0e [2] f5 0e [2] ca 12 }

  condition:
    any of them
}