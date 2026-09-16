rule TTP_XOR_WriteProcessMemory_b813 {
  strings:
    $key_b813 = { ef 61 [2] dd 43 [2] db 76 [2] f5 76 [2] ca 6a }

  condition:
    any of them
}