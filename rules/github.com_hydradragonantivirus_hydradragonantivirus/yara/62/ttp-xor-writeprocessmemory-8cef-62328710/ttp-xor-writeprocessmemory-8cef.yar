rule TTP_XOR_WriteProcessMemory_8cef {
  strings:
    $key_8cef = { db 9d [2] e9 bf [2] ef 8a [2] c1 8a [2] fe 96 }

  condition:
    any of them
}