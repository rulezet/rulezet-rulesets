rule TTP_XOR_WriteProcessMemory_b866 {
  strings:
    $key_b866 = { ef 14 [2] dd 36 [2] db 03 [2] f5 03 [2] ca 1f }

  condition:
    any of them
}