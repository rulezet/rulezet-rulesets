rule TTP_XOR_WriteProcessMemory_b88c {
  strings:
    $key_b88c = { ef fe [2] dd dc [2] db e9 [2] f5 e9 [2] ca f5 }

  condition:
    any of them
}