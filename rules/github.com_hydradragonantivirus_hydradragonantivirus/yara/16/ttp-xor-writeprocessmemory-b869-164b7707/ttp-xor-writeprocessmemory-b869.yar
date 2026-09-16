rule TTP_XOR_WriteProcessMemory_b869 {
  strings:
    $key_b869 = { ef 1b [2] dd 39 [2] db 0c [2] f5 0c [2] ca 10 }

  condition:
    any of them
}