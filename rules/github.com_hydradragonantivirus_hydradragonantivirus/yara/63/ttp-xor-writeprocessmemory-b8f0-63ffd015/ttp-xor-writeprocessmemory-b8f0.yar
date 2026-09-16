rule TTP_XOR_WriteProcessMemory_b8f0 {
  strings:
    $key_b8f0 = { ef 82 [2] dd a0 [2] db 95 [2] f5 95 [2] ca 89 }

  condition:
    any of them
}