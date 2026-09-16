rule TTP_XOR_WriteProcessMemory_b38b {
  strings:
    $key_b38b = { e4 f9 [2] d6 db [2] d0 ee [2] fe ee [2] c1 f2 }

  condition:
    any of them
}