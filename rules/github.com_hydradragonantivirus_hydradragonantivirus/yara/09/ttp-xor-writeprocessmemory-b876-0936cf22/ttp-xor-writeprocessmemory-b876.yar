rule TTP_XOR_WriteProcessMemory_b876 {
  strings:
    $key_b876 = { ef 04 [2] dd 26 [2] db 13 [2] f5 13 [2] ca 0f }

  condition:
    any of them
}