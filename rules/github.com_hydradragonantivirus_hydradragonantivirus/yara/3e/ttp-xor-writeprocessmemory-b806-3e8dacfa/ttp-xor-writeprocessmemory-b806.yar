rule TTP_XOR_WriteProcessMemory_b806 {
  strings:
    $key_b806 = { ef 74 [2] dd 56 [2] db 63 [2] f5 63 [2] ca 7f }

  condition:
    any of them
}