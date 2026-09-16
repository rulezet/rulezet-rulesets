rule TTP_XOR_WriteProcessMemory_b87b {
  strings:
    $key_b87b = { ef 09 [2] dd 2b [2] db 1e [2] f5 1e [2] ca 02 }

  condition:
    any of them
}