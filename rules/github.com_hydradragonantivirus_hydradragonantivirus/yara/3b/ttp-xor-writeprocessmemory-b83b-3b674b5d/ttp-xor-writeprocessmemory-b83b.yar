rule TTP_XOR_WriteProcessMemory_b83b {
  strings:
    $key_b83b = { ef 49 [2] dd 6b [2] db 5e [2] f5 5e [2] ca 42 }

  condition:
    any of them
}