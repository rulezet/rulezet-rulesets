rule TTP_XOR_WriteProcessMemory_b82b {
  strings:
    $key_b82b = { ef 59 [2] dd 7b [2] db 4e [2] f5 4e [2] ca 52 }

  condition:
    any of them
}