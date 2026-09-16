rule TTP_XOR_WriteProcessMemory_b858 {
  strings:
    $key_b858 = { ef 2a [2] dd 08 [2] db 3d [2] f5 3d [2] ca 21 }

  condition:
    any of them
}