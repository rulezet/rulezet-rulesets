rule TTP_XOR_WriteProcessMemory_b3ce {
  strings:
    $key_b3ce = { e4 bc [2] d6 9e [2] d0 ab [2] fe ab [2] c1 b7 }

  condition:
    any of them
}