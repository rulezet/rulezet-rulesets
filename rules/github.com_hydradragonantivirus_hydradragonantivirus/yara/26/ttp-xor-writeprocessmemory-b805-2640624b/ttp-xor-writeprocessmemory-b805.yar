rule TTP_XOR_WriteProcessMemory_b805 {
  strings:
    $key_b805 = { ef 77 [2] dd 55 [2] db 60 [2] f5 60 [2] ca 7c }

  condition:
    any of them
}