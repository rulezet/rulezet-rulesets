rule TTP_XOR_WriteProcessMemory_b845 {
  strings:
    $key_b845 = { ef 37 [2] dd 15 [2] db 20 [2] f5 20 [2] ca 3c }

  condition:
    any of them
}