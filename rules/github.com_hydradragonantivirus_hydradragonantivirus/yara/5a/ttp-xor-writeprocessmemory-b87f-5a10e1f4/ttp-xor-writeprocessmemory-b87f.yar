rule TTP_XOR_WriteProcessMemory_b87f {
  strings:
    $key_b87f = { ef 0d [2] dd 2f [2] db 1a [2] f5 1a [2] ca 06 }

  condition:
    any of them
}