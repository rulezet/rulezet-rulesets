rule TTP_XOR_WriteProcessMemory_b844 {
  strings:
    $key_b844 = { ef 36 [2] dd 14 [2] db 21 [2] f5 21 [2] ca 3d }

  condition:
    any of them
}