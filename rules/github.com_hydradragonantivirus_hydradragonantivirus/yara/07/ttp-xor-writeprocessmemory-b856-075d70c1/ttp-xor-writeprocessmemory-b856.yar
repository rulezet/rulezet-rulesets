rule TTP_XOR_WriteProcessMemory_b856 {
  strings:
    $key_b856 = { ef 24 [2] dd 06 [2] db 33 [2] f5 33 [2] ca 2f }

  condition:
    any of them
}