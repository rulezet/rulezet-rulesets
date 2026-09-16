rule TTP_XOR_WriteProcessMemory_b83e {
  strings:
    $key_b83e = { ef 4c [2] dd 6e [2] db 5b [2] f5 5b [2] ca 47 }

  condition:
    any of them
}