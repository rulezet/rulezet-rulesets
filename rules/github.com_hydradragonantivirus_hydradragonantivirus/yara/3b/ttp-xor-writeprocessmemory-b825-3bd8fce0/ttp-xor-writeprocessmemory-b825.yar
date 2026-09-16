rule TTP_XOR_WriteProcessMemory_b825 {
  strings:
    $key_b825 = { ef 57 [2] dd 75 [2] db 40 [2] f5 40 [2] ca 5c }

  condition:
    any of them
}