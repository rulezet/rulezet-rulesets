rule TTP_XOR_WriteProcessMemory_b818 {
  strings:
    $key_b818 = { ef 6a [2] dd 48 [2] db 7d [2] f5 7d [2] ca 61 }

  condition:
    any of them
}