rule TTP_XOR_WriteProcessMemory_8c54 {
  strings:
    $key_8c54 = { db 26 [2] e9 04 [2] ef 31 [2] c1 31 [2] fe 2d }

  condition:
    any of them
}