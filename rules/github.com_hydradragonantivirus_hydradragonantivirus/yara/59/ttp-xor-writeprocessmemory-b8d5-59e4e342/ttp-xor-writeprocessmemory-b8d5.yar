rule TTP_XOR_WriteProcessMemory_b8d5 {
  strings:
    $key_b8d5 = { ef a7 [2] dd 85 [2] db b0 [2] f5 b0 [2] ca ac }

  condition:
    any of them
}