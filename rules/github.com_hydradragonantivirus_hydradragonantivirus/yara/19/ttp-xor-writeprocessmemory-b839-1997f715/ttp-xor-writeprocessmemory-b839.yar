rule TTP_XOR_WriteProcessMemory_b839 {
  strings:
    $key_b839 = { ef 4b [2] dd 69 [2] db 5c [2] f5 5c [2] ca 40 }

  condition:
    any of them
}