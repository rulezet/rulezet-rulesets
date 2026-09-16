rule TTP_XOR_WriteProcessMemory_b8d7 {
  strings:
    $key_b8d7 = { ef a5 [2] dd 87 [2] db b2 [2] f5 b2 [2] ca ae }

  condition:
    any of them
}