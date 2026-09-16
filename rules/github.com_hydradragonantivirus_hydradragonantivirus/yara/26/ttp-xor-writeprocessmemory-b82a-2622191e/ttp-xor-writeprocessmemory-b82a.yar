rule TTP_XOR_WriteProcessMemory_b82a {
  strings:
    $key_b82a = { ef 58 [2] dd 7a [2] db 4f [2] f5 4f [2] ca 53 }

  condition:
    any of them
}