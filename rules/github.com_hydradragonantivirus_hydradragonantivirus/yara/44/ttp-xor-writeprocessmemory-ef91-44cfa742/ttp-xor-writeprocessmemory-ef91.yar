rule TTP_XOR_WriteProcessMemory_ef91 {
  strings:
    $key_ef91 = { b8 e3 [2] 8a c1 [2] 8c f4 [2] a2 f4 [2] 9d e8 }

  condition:
    any of them
}