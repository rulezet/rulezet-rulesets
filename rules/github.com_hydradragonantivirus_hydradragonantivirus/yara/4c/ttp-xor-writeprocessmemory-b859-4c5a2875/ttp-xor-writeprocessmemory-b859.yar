rule TTP_XOR_WriteProcessMemory_b859 {
  strings:
    $key_b859 = { ef 2b [2] dd 09 [2] db 3c [2] f5 3c [2] ca 20 }

  condition:
    any of them
}