rule TTP_XOR_WriteProcessMemory_b8ea {
  strings:
    $key_b8ea = { ef 98 [2] dd ba [2] db 8f [2] f5 8f [2] ca 93 }

  condition:
    any of them
}