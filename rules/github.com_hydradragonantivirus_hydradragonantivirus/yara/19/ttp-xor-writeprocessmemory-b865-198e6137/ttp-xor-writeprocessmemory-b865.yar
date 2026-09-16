rule TTP_XOR_WriteProcessMemory_b865 {
  strings:
    $key_b865 = { ef 17 [2] dd 35 [2] db 00 [2] f5 00 [2] ca 1c }

  condition:
    any of them
}