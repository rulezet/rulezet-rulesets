rule TTP_XOR_WriteProcessMemory_b8c2 {
  strings:
    $key_b8c2 = { ef b0 [2] dd 92 [2] db a7 [2] f5 a7 [2] ca bb }

  condition:
    any of them
}