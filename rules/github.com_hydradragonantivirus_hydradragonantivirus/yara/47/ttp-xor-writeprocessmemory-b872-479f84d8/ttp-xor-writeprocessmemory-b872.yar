rule TTP_XOR_WriteProcessMemory_b872 {
  strings:
    $key_b872 = { ef 00 [2] dd 22 [2] db 17 [2] f5 17 [2] ca 0b }

  condition:
    any of them
}