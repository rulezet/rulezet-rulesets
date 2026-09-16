rule TTP_XOR_WriteProcessMemory_b8f9 {
  strings:
    $key_b8f9 = { ef 8b [2] dd a9 [2] db 9c [2] f5 9c [2] ca 80 }

  condition:
    any of them
}