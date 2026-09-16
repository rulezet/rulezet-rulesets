rule TTP_XOR_WriteProcessMemory_b821 {
  strings:
    $key_b821 = { ef 53 [2] dd 71 [2] db 44 [2] f5 44 [2] ca 58 }

  condition:
    any of them
}