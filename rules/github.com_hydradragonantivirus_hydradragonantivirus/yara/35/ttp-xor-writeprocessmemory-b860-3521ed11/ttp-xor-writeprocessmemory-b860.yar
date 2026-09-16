rule TTP_XOR_WriteProcessMemory_b860 {
  strings:
    $key_b860 = { ef 12 [2] dd 30 [2] db 05 [2] f5 05 [2] ca 19 }

  condition:
    any of them
}