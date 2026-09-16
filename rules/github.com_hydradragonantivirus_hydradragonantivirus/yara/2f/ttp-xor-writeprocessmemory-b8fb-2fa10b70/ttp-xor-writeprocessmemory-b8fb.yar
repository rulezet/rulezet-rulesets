rule TTP_XOR_WriteProcessMemory_b8fb {
  strings:
    $key_b8fb = { ef 89 [2] dd ab [2] db 9e [2] f5 9e [2] ca 82 }

  condition:
    any of them
}