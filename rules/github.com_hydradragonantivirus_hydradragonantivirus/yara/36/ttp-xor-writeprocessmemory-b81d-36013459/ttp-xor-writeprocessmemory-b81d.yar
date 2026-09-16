rule TTP_XOR_WriteProcessMemory_b81d {
  strings:
    $key_b81d = { ef 6f [2] dd 4d [2] db 78 [2] f5 78 [2] ca 64 }

  condition:
    any of them
}