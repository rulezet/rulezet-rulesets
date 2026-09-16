rule TTP_XOR_WriteProcessMemory_b8ee {
  strings:
    $key_b8ee = { ef 9c [2] dd be [2] db 8b [2] f5 8b [2] ca 97 }

  condition:
    any of them
}