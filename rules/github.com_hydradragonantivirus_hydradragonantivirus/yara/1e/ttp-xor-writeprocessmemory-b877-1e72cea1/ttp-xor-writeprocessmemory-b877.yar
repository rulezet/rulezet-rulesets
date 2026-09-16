rule TTP_XOR_WriteProcessMemory_b877 {
  strings:
    $key_b877 = { ef 05 [2] dd 27 [2] db 12 [2] f5 12 [2] ca 0e }

  condition:
    any of them
}