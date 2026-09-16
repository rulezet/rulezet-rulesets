rule TTP_XOR_WriteProcessMemory_b819 {
  strings:
    $key_b819 = { ef 6b [2] dd 49 [2] db 7c [2] f5 7c [2] ca 60 }

  condition:
    any of them
}