rule TTP_XOR_WriteProcessMemory_be8c {
  strings:
    $key_be8c = { e9 fe [2] db dc [2] dd e9 [2] f3 e9 [2] cc f5 }

  condition:
    any of them
}