rule TTP_XOR_WriteProcessMemory_8c18 {
  strings:
    $key_8c18 = { db 6a [2] e9 48 [2] ef 7d [2] c1 7d [2] fe 61 }

  condition:
    any of them
}