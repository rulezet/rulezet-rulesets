rule TTP_XOR_WriteProcessMemory_b873 {
  strings:
    $key_b873 = { ef 01 [2] dd 23 [2] db 16 [2] f5 16 [2] ca 0a }

  condition:
    any of them
}