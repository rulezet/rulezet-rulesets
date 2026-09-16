rule TTP_XOR_WriteProcessMemory_b86a {
  strings:
    $key_b86a = { ef 18 [2] dd 3a [2] db 0f [2] f5 0f [2] ca 13 }

  condition:
    any of them
}