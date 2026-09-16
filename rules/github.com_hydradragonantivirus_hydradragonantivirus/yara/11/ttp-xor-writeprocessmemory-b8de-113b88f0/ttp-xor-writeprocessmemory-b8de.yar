rule TTP_XOR_WriteProcessMemory_b8de {
  strings:
    $key_b8de = { ef ac [2] dd 8e [2] db bb [2] f5 bb [2] ca a7 }

  condition:
    any of them
}