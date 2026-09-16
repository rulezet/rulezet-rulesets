rule TTP_XOR_WriteProcessMemory_b814 {
  strings:
    $key_b814 = { ef 66 [2] dd 44 [2] db 71 [2] f5 71 [2] ca 6d }

  condition:
    any of them
}