rule TTP_XOR_WriteProcessMemory_b80a {
  strings:
    $key_b80a = { ef 78 [2] dd 5a [2] db 6f [2] f5 6f [2] ca 73 }

  condition:
    any of them
}