rule TTP_XOR_WriteProcessMemory_b81a {
  strings:
    $key_b81a = { ef 68 [2] dd 4a [2] db 7f [2] f5 7f [2] ca 63 }

  condition:
    any of them
}