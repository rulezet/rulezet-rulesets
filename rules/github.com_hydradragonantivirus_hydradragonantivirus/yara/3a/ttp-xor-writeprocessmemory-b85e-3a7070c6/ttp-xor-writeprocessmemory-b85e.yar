rule TTP_XOR_WriteProcessMemory_b85e {
  strings:
    $key_b85e = { ef 2c [2] dd 0e [2] db 3b [2] f5 3b [2] ca 27 }

  condition:
    any of them
}