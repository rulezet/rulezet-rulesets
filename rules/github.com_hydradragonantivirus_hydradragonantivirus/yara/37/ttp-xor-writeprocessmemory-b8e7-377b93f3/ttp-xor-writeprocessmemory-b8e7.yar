rule TTP_XOR_WriteProcessMemory_b8e7 {
  strings:
    $key_b8e7 = { ef 95 [2] dd b7 [2] db 82 [2] f5 82 [2] ca 9e }

  condition:
    any of them
}