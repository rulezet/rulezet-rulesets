rule TTP_XOR_WriteProcessMemory_b8f4 {
  strings:
    $key_b8f4 = { ef 86 [2] dd a4 [2] db 91 [2] f5 91 [2] ca 8d }

  condition:
    any of them
}