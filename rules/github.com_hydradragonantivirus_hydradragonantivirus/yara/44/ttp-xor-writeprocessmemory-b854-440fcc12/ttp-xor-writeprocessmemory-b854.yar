rule TTP_XOR_WriteProcessMemory_b854 {
  strings:
    $key_b854 = { ef 26 [2] dd 04 [2] db 31 [2] f5 31 [2] ca 2d }

  condition:
    any of them
}