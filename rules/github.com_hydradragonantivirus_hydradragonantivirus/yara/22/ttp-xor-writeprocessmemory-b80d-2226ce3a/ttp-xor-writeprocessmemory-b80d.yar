rule TTP_XOR_WriteProcessMemory_b80d {
  strings:
    $key_b80d = { ef 7f [2] dd 5d [2] db 68 [2] f5 68 [2] ca 74 }

  condition:
    any of them
}