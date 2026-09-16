rule TTP_XOR_WriteProcessMemory_b83a {
  strings:
    $key_b83a = { ef 48 [2] dd 6a [2] db 5f [2] f5 5f [2] ca 43 }

  condition:
    any of them
}