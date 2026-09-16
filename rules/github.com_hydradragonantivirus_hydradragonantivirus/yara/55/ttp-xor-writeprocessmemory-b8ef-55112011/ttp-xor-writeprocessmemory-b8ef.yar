rule TTP_XOR_WriteProcessMemory_b8ef {
  strings:
    $key_b8ef = { ef 9d [2] dd bf [2] db 8a [2] f5 8a [2] ca 96 }

  condition:
    any of them
}