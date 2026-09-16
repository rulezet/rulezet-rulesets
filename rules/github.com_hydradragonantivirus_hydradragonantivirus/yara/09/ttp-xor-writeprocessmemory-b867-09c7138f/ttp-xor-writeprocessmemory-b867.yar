rule TTP_XOR_WriteProcessMemory_b867 {
  strings:
    $key_b867 = { ef 15 [2] dd 37 [2] db 02 [2] f5 02 [2] ca 1e }

  condition:
    any of them
}