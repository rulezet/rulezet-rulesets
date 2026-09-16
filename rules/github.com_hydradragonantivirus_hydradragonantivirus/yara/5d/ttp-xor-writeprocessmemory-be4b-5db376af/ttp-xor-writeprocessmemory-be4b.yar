rule TTP_XOR_WriteProcessMemory_be4b {
  strings:
    $key_be4b = { e9 39 [2] db 1b [2] dd 2e [2] f3 2e [2] cc 32 }

  condition:
    any of them
}