rule TTP_XOR_WriteProcessMemory_b823 {
  strings:
    $key_b823 = { ef 51 [2] dd 73 [2] db 46 [2] f5 46 [2] ca 5a }

  condition:
    any of them
}