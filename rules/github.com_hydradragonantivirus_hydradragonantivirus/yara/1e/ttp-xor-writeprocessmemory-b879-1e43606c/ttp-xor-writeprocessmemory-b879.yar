rule TTP_XOR_WriteProcessMemory_b879 {
  strings:
    $key_b879 = { ef 0b [2] dd 29 [2] db 1c [2] f5 1c [2] ca 00 }

  condition:
    any of them
}