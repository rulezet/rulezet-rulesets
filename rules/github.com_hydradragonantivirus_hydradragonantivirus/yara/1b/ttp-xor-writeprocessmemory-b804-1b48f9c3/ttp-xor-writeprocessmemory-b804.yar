rule TTP_XOR_WriteProcessMemory_b804 {
  strings:
    $key_b804 = { ef 76 [2] dd 54 [2] db 61 [2] f5 61 [2] ca 7d }

  condition:
    any of them
}