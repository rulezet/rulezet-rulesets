rule TTP_XOR_WriteProcessMemory_b86e {
  strings:
    $key_b86e = { ef 1c [2] dd 3e [2] db 0b [2] f5 0b [2] ca 17 }

  condition:
    any of them
}