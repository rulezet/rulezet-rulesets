rule TTP_XOR_WriteProcessMemory_b827 {
  strings:
    $key_b827 = { ef 55 [2] dd 77 [2] db 42 [2] f5 42 [2] ca 5e }

  condition:
    any of them
}