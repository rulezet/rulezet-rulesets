rule TTP_XOR_WriteProcessMemory_b836 {
  strings:
    $key_b836 = { ef 44 [2] dd 66 [2] db 53 [2] f5 53 [2] ca 4f }

  condition:
    any of them
}