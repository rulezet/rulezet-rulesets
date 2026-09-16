rule TTP_XOR_WriteProcessMemory_ef8c {
  strings:
    $key_ef8c = { b8 fe [2] 8a dc [2] 8c e9 [2] a2 e9 [2] 9d f5 }

  condition:
    any of them
}