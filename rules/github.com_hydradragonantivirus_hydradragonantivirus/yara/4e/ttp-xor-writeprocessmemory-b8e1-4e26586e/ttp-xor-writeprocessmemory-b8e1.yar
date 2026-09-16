rule TTP_XOR_WriteProcessMemory_b8e1 {
  strings:
    $key_b8e1 = { ef 93 [2] dd b1 [2] db 84 [2] f5 84 [2] ca 98 }

  condition:
    any of them
}