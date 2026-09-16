rule TTP_XOR_WriteProcessMemory_b828 {
  strings:
    $key_b828 = { ef 5a [2] dd 78 [2] db 4d [2] f5 4d [2] ca 51 }

  condition:
    any of them
}