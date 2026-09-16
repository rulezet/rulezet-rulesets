rule TTP_XOR_WriteProcessMemory_b8e0 {
  strings:
    $key_b8e0 = { ef 92 [2] dd b0 [2] db 85 [2] f5 85 [2] ca 99 }

  condition:
    any of them
}