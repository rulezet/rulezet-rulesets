rule TTP_XOR_WriteProcessMemory_b86f {
  strings:
    $key_b86f = { ef 1d [2] dd 3f [2] db 0a [2] f5 0a [2] ca 16 }

  condition:
    any of them
}