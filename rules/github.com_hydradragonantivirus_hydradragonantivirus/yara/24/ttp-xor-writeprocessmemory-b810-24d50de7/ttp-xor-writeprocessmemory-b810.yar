rule TTP_XOR_WriteProcessMemory_b810 {
  strings:
    $key_b810 = { ef 62 [2] dd 40 [2] db 75 [2] f5 75 [2] ca 69 }

  condition:
    any of them
}