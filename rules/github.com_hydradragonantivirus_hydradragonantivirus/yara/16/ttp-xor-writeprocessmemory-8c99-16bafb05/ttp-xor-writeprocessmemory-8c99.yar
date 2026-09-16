rule TTP_XOR_WriteProcessMemory_8c99 {
  strings:
    $key_8c99 = { db eb [2] e9 c9 [2] ef fc [2] c1 fc [2] fe e0 }

  condition:
    any of them
}