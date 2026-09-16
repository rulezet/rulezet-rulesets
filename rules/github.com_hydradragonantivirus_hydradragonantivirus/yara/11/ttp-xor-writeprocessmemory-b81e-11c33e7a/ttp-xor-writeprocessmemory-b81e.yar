rule TTP_XOR_WriteProcessMemory_b81e {
  strings:
    $key_b81e = { ef 6c [2] dd 4e [2] db 7b [2] f5 7b [2] ca 67 }

  condition:
    any of them
}