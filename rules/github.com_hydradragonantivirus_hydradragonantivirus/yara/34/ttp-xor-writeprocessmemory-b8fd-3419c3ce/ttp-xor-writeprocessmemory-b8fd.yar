rule TTP_XOR_WriteProcessMemory_b8fd {
  strings:
    $key_b8fd = { ef 8f [2] dd ad [2] db 98 [2] f5 98 [2] ca 84 }

  condition:
    any of them
}