rule TTP_XOR_WriteProcessMemory_b826 {
  strings:
    $key_b826 = { ef 54 [2] dd 76 [2] db 43 [2] f5 43 [2] ca 5f }

  condition:
    any of them
}