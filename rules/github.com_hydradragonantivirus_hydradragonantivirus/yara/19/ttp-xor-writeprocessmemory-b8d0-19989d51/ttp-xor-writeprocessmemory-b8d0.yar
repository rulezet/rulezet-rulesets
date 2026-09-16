rule TTP_XOR_WriteProcessMemory_b8d0 {
  strings:
    $key_b8d0 = { ef a2 [2] dd 80 [2] db b5 [2] f5 b5 [2] ca a9 }

  condition:
    any of them
}