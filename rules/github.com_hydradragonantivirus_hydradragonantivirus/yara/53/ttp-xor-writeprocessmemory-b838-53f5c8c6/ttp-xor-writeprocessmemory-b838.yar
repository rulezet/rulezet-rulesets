rule TTP_XOR_WriteProcessMemory_b838 {
  strings:
    $key_b838 = { ef 4a [2] dd 68 [2] db 5d [2] f5 5d [2] ca 41 }

  condition:
    any of them
}