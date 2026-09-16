rule TTP_XOR_WriteProcessMemory_b82c {
  strings:
    $key_b82c = { ef 5e [2] dd 7c [2] db 49 [2] f5 49 [2] ca 55 }

  condition:
    any of them
}