rule TTP_XOR_WriteProcessMemory_b842 {
  strings:
    $key_b842 = { ef 30 [2] dd 12 [2] db 27 [2] f5 27 [2] ca 3b }

  condition:
    any of them
}