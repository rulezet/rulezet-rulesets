rule TTP_XOR_WriteProcessMemory_b8f3 {
  strings:
    $key_b8f3 = { ef 81 [2] dd a3 [2] db 96 [2] f5 96 [2] ca 8a }

  condition:
    any of them
}