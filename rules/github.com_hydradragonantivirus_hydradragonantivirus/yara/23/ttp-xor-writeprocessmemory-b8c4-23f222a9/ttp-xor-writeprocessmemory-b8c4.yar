rule TTP_XOR_WriteProcessMemory_b8c4 {
  strings:
    $key_b8c4 = { ef b6 [2] dd 94 [2] db a1 [2] f5 a1 [2] ca bd }

  condition:
    any of them
}