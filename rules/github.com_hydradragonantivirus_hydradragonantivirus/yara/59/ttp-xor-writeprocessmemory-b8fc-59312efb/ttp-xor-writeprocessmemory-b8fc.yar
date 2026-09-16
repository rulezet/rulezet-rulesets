rule TTP_XOR_WriteProcessMemory_b8fc {
  strings:
    $key_b8fc = { ef 8e [2] dd ac [2] db 99 [2] f5 99 [2] ca 85 }

  condition:
    any of them
}